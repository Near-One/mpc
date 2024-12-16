use futures::FutureExt;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::future::Future;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;
use tokio::task::{JoinError, JoinSet};
use tokio::task_local;

/// A wrapper around JoinHandle, except that dropping this will abort the task
/// behind the handle. This is very useful in making sure that background tasks
/// spawned by futures that are then dropped are are properly cleaned up.
#[must_use = "Dropping this value will immediately abort the task"]
pub struct AutoAbortTask<R> {
    handle: tokio::task::JoinHandle<R>,
}

impl<R> Drop for AutoAbortTask<R> {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl<R> From<tokio::task::JoinHandle<R>> for AutoAbortTask<R> {
    fn from(handle: tokio::task::JoinHandle<R>) -> Self {
        Self { handle }
    }
}

/// Mimics the same Future semantics as the underlying JoinHandle.
impl<R> Future for AutoAbortTask<R> {
    type Output = Result<R, JoinError>;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.handle.poll_unpin(cx)
    }
}

/// Spawns a new task that is a child of the current tokio task.
/// Must be called from a tracked tokio task.
/// Unlike tokio::spawn, the returned `AutoAbortTask` will abort the task if it
/// is dropped, so the caller must explicitly decide on when the spawned task
/// would continue to exist.
pub fn spawn<F, R>(description: &str, f: F) -> AutoAbortTask<R>
where
    F: Future<Output = R> + Send + 'static,
    R: Send + 'static,
{
    tokio::spawn(current_task().scope(description, f)).into()
}

/// Like `spawn`, but if the task resolves to an error result, logs the result.
/// This swallows the result, so it should only be used for spawns whose results
/// are not handled.
pub fn spawn_checked<F, R>(description: &str, f: F) -> AutoAbortTask<()>
where
    F: Future<Output = anyhow::Result<R>> + Send + 'static,
    R: Send + 'static,
{
    tokio::spawn(current_task().scope_checked(description, f)).into()
}

/// A collection of tasks that should all be aborted when the collection itself
/// is dropped. It is acceptable to spawn an unbounded number of tasks into this
/// collection, as it automatically cleans up tasks that have already completed.
pub struct AutoAbortTaskCollection<R> {
    join_set: JoinSet<R>,
}

impl<R: Send + 'static> AutoAbortTaskCollection<R> {
    pub fn new() -> Self {
        Self {
            join_set: JoinSet::new(),
        }
    }
}

impl AutoAbortTaskCollection<()> {
    /// Like the free function spawn_checked, but spawns the task into the
    /// `AutoAbortTaskCollection`.
    /// Note: there's no `spawn` function. This is because if we want to spawn
    /// a task into such a collection, then this task is a fire-and-forget task,
    /// so an error should always be printed out.
    pub fn spawn_checked<F, R>(&mut self, description: &str, f: F)
    where
        R: Send + 'static,
        F: Future<Output = anyhow::Result<R>> + Send + 'static,
    {
        self.join_set
            .spawn(current_task().scope_checked(description, f));
        // JoinSet itself keeps expired tasks until they are joined on. So we do
        // some cleanup here to join any tasks that have already completed.
        while self.join_set.try_join_next().is_some() {}
    }
}

/// Reports the progress of the current tokio task.
/// Must be called from a tracked tokio task.
pub fn set_progress(progress: &str) {
    CURRENT_TASK.with(|task| task.0.set_progress(progress));
}

/// Starts a root task. This is the entry point for tracking tasks.
/// All other futures must be spawned with `tracking::spawn`, rather than
/// `tokio::spawn`.
pub fn start_root_task<F, R>(f: F) -> (impl Future<Output = R>, Arc<TaskHandle>)
where
    F: Future<Output = R> + Send + 'static,
    R: Send + 'static,
{
    let handle = Arc::new(TaskHandle {
        _parent: None,
        children: Mutex::new(WeakCollection::new()),
        description: "root".to_string(),
        start_time: Instant::now(),
        progress: Mutex::new(("".to_string(), Instant::now())),
        finished: AtomicBool::new(false),
    });
    (
        CURRENT_TASK.scope(Arc::new(TaskHandleScoped(handle.clone())), f),
        handle,
    )
}

/// Returns the handle to the current task.
/// Must be called from a tracked tokio task.
pub fn current_task() -> Arc<TaskHandle> {
    CURRENT_TASK.get().0.clone()
}

/// Simple self-garbage-collecting ordered collection of weak references.
/// Used to keep track of children tasks that may have finished.
/// It works by checking 2 references for every push, making it O(1).
struct WeakCollection<T> {
    buffers: [VecDeque<Weak<T>>; 2],
    current: usize,
}

impl<T> WeakCollection<T> {
    fn new() -> Self {
        Self {
            buffers: [VecDeque::new(), VecDeque::new()],
            current: 0,
        }
    }

    fn push(&mut self, item: Weak<T>) {
        self.buffers[self.current].push_back(item);
        self.remove_some_expired_references();
    }

    fn remove_some_expired_references(&mut self) {
        for _ in 0..2 {
            match self.buffers[self.current].pop_front() {
                Some(item) => {
                    if item.strong_count() > 0 {
                        self.buffers[1 - self.current].push_back(item);
                    }
                }
                None => {
                    self.current = 1 - self.current;
                    continue;
                }
            }
        }
    }

    fn iter(&self) -> impl Iterator<Item = Arc<T>> + '_ {
        self.buffers[1 - self.current]
            .iter()
            .chain(self.buffers[self.current].iter())
            .filter_map(|weak| weak.upgrade())
    }
}

/// Tracks the execution progress of a future. It is referenced in three ways:
///  - As a parent of other tasks that this task spawned. While these tasks are
///    alive, we keep the parent around for information.
///  - By a future's task-local variable. This reference goes away when the
///    future drops the task-local (i.e. when it's finished), which is also
///    when we mark this task as finished.
///  - Weakly, by its parent's children collection. This is used to locate all
///    the currently running tasks for debugging purposes.
pub struct TaskHandle {
    _parent: Option<Arc<TaskHandle>>, // This is needed to keep the parent alive
    children: Mutex<WeakCollection<TaskHandle>>,
    description: String,
    start_time: Instant,
    progress: Mutex<(String, Instant)>,
    finished: AtomicBool,
}

/// A task handle, but marks the task handle as finished when it is dropped.
struct TaskHandleScoped(Arc<TaskHandle>);

impl Drop for TaskHandleScoped {
    fn drop(&mut self) {
        self.0
            .finished
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

task_local! {
    // This is used by a future to query the current TaskHandle.
    static CURRENT_TASK: Arc<TaskHandleScoped>;
}

impl TaskHandle {
    pub fn set_progress(&self, progress: &str) {
        let mut progress_lock = self.progress.lock().unwrap();
        *progress_lock = (progress.to_string(), Instant::now());
    }

    fn new_child(self: &Arc<TaskHandle>, description: &str) -> Arc<TaskHandle> {
        let description = description.to_string();
        let progress = Mutex::new(("".to_string(), Instant::now()));
        let handle = Arc::new(TaskHandle {
            _parent: Some(self.clone()),
            children: Mutex::new(WeakCollection::new()),
            description,
            start_time: Instant::now(),
            progress,
            finished: AtomicBool::new(false),
        });
        self.children.lock().unwrap().push(Arc::downgrade(&handle));
        handle
    }

    /// Forces the future to run in the scope of the given task handle.
    /// Useful when there's a tracking gap due to a third party library
    /// (such as actix_web) spawning futures with tokio::spawn.
    pub fn scope<F, R>(self: &Arc<TaskHandle>, description: &str, f: F) -> impl Future<Output = R>
    where
        F: Future<Output = R> + Send + 'static,
        R: Send + 'static,
    {
        let child = self.new_child(description);
        CURRENT_TASK.scope(Arc::new(TaskHandleScoped(child)), f)
    }

    /// Forces the future to run in the scope of the given task handle.
    /// Useful when there's a tracking gap due to a third party library
    /// (such as actix_web) spawning futures with tokio::spawn.
    /// In addition, if the future returns with an error, logs the error.
    pub fn scope_checked<F, R>(
        self: &Arc<TaskHandle>,
        description: &str,
        f: F,
    ) -> impl Future<Output = ()>
    where
        F: Future<Output = anyhow::Result<R>> + Send + 'static,
        R: Send + 'static,
    {
        let child = self.new_child(description);
        let description_clone = description.to_string();
        let child_clone = child.clone();
        CURRENT_TASK.scope(Arc::new(TaskHandleScoped(child)), async move {
            let result = f.await;
            if let Err(err) = result {
                tracing::error!(
                    "Task failed: {}: {}; last status: {}",
                    description_clone,
                    err,
                    child_clone.progress.lock().unwrap().0
                );
            }
        })
    }

    pub fn report(&self) -> TaskStatusReport {
        let children_handles = self.children.lock().unwrap().iter().collect::<Vec<_>>();
        let children_reports = children_handles
            .into_iter()
            .map(|child| child.report())
            .collect();
        let progress = self.progress.lock().unwrap();
        let progress_string = progress.0.clone();
        let progress_elapsed = progress.1.elapsed();
        drop(progress);
        TaskStatusReport {
            description: self.description.clone(),
            progress: progress_string,
            progress_elapsed,
            elapsed: self.start_time.elapsed(),
            finished: self.finished.load(std::sync::atomic::Ordering::Relaxed),
            children: children_reports,
        }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct TaskStatusReport {
    description: String,
    progress: String,
    progress_elapsed: std::time::Duration,
    elapsed: std::time::Duration,
    finished: bool,
    children: Vec<TaskStatusReport>,
}

impl Debug for TaskStatusReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn format_duration(duration: std::time::Duration) -> String {
            if duration.as_secs() > 60 {
                format!("{}m", duration.as_secs() / 60)
            } else if duration.as_secs() >= 1 {
                format!("{}s", duration.as_secs())
            } else {
                "<1s".to_string()
            }
        }
        fn format_short_duration(duration: std::time::Duration) -> String {
            if duration.as_secs() > 60 {
                format!("{}m", duration.as_secs() / 60)
            } else if duration.as_secs() >= 1 {
                format!("{}s", duration.as_secs())
            } else {
                format!("{}ms", duration.as_millis())
            }
        }
        fn fmt_inner(
            report: &TaskStatusReport,
            f: &mut std::fmt::Formatter<'_>,
            indent: usize,
        ) -> std::fmt::Result {
            writeln!(
                f,
                "{}[{}] {:>3} {}: {} (for {})",
                " ".repeat(indent),
                if report.finished { "✔" } else { " " },
                format_duration(report.elapsed),
                report.description,
                report.progress,
                format_short_duration(report.progress_elapsed),
            )?;
            for child in &report.children {
                fmt_inner(child, f, indent + 2)?;
            }
            Ok(())
        }
        fmt_inner(self, f, 0)
    }
}

#[cfg(test)]
pub mod testing {
    /// Runs the top-most-level future with tracking, and prints a report of
    /// running tasks every 5 seconds.
    pub fn start_root_task_with_periodic_dump<F, R>(f: F) -> impl std::future::Future<Output = R>
    where
        F: std::future::Future<Output = R> + Send + 'static,
        R: Send + 'static,
    {
        let (future, handle) = super::start_root_task(f);
        let handle_clone = handle.clone();
        tokio::spawn(async move {
            loop {
                let report = handle_clone.report();
                eprintln!("{:?}", report);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
        future
    }
}
