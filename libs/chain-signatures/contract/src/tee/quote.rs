use anyhow::Result;
use dcap_qvl::{quote::Quote, verify::VerifiedReport, QuoteCollateralV3};
use hex::{decode, encode};
use k256::sha2::{Digest as _, Sha256, Sha384};
use near_sdk::{near, require};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeeQuoteStatus {
    None,
    Valid,
    Invalid,
}

impl From<Result<VerifiedReport, crate::Error>> for TeeQuoteStatus {
    fn from(result: Result<VerifiedReport, crate::Error>) -> Self {
        match result {
            Ok(_) => TeeQuoteStatus::Valid,
            Err(_) => TeeQuoteStatus::Invalid,
        }
    }
}

/// Remote Attestation TDX quote.
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct TeeQuote(pub(crate) Vec<u8>);

impl TeeQuote {
    pub fn new(data: Vec<u8>) -> Self {
        TeeQuote(data)
    }

    pub fn get_quote(&self) -> Result<Quote> {
        Quote::parse(&self.0)
    }

    pub fn get_rtmr3(&self) -> Result<[u8; 48]> {
        let quote = self.get_quote()?;
        Ok(quote.report.as_td10().unwrap().rt_mr3)
    }
}

/// Parses the raw JSON string into a QuoteCollateralV3 structure.
pub fn get_collateral(raw: String) -> QuoteCollateralV3 {
    fn get_str(v: &Value, key: &str) -> String {
        v.get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| panic!("Missing or invalid field: {}", key))
    }

    fn get_hex(v: &Value, key: &str) -> Vec<u8> {
        hex::decode(get_str(v, key)).unwrap_or_else(|_| panic!("Failed to decode hex: {}", key))
    }

    let v: Value = serde_json::from_str(&raw).expect("Invalid quote collateral JSON");

    QuoteCollateralV3 {
        tcb_info_issuer_chain: get_str(&v, "tcb_info_issuer_chain"),
        tcb_info: get_str(&v, "tcb_info"),
        tcb_info_signature: get_hex(&v, "tcb_info_signature"),
        qe_identity_issuer_chain: get_str(&v, "qe_identity_issuer_chain"),
        qe_identity: get_str(&v, "qe_identity"),
        qe_identity_signature: get_hex(&v, "qe_identity_signature"),
    }
}

pub fn verify_codehash(raw_tcb_info: String, rtmr3: String) -> String {
    let tcb_info: Value =
        serde_json::from_str(&raw_tcb_info).expect("TCB Info should be valid JSON");
    let event_log = tcb_info["event_log"].as_array().unwrap();
    // get compose hash from events
    let expected_compose_hash = event_log
        .iter()
        .find(|e| e["event"].as_str().unwrap() == "compose-hash")
        .unwrap()["digest"]
        .as_str()
        .unwrap();

    // replay the rtmr3 and compose hash
    let replayed_rtmr3 = replay_rtmr(event_log.to_owned(), 3);
    let app_compose = tcb_info["app_compose"].as_str().unwrap();
    let replayed_compose_hash = replay_app_compose(app_compose);

    // compose hash match expected
    require!(replayed_compose_hash == expected_compose_hash);
    // event with compose hash matches report rtmr3
    require!(replayed_rtmr3 == rtmr3);

    let (_, right) = app_compose.split_once("\\n        image:").unwrap();
    let (left, _) = right.split_once("\\n").unwrap();
    let (_, codehash) = left.split_once("@sha256:").unwrap();

    codehash.to_owned()
}

// helpers

fn replay_rtmr(event_log: Vec<Value>, imr: u8) -> String {
    let mut digest = [0u8; 48];

    // filter by imr
    let filtered_events = event_log
        .iter()
        .filter(|e| e["imr"].as_u64().unwrap() as u8 == imr);

    // hash all digests together
    for event in filtered_events {
        let mut hasher = Sha384::new();
        hasher.update(digest);
        hasher.update(
            decode(event["digest"].as_str().unwrap())
                .unwrap()
                .as_slice(),
        );
        digest = hasher.finalize().into();
    }

    // return hex encoded digest (rtmr[imr])
    encode(digest)
}

fn replay_app_compose(app_compose: &str) -> String {
    // sha256 of app_compose from TcbInfo
    let mut sha256 = Sha256::new();
    sha256.update(app_compose);
    let sha256bytes: [u8; 32] = sha256.finalize().into();

    // sha384 of custom encoding: [phala_prefix]:[event_name]:[sha256_payload]
    let mut hasher = Sha384::new();
    hasher.update(vec![0x01, 0x00, 0x00, 0x08]);
    hasher.update(b":");
    hasher.update("compose-hash".as_bytes());
    hasher.update(b":");
    hasher.update(sha256bytes);
    let digest: [u8; 48] = hasher.finalize().into();

    encode(digest)
}

#[test]
fn test() {
    use dcap_qvl::verify;
    use hex::decode;
    use serde_json::json;

    let tcb_info = json!(
        {
            "rootfs_hash": "738ae348dbf674b3399300c0b9416c203e9b645c6ffee233035d09003cccad12f71becc805ad8d97575bc790c6819216",
            "mrtd": "c68518a0ebb42136c12b2275164f8c72f25fa9a34392228687ed6e9caeb9c0f1dbd895e9cf475121c029dc47e70e91fd",
            "rtmr0": "85e0855a6384fa1c8a6ab36d0dcbfaa11a5753e5a070c08218ae5fe872fcb86967fd2449c29e22e59dc9fec998cb6547",
            "rtmr1": "4a7db64a609c77e85f603c23e9a9fd03bfd9e6b52ce527f774a598e66d58386026cea79b2aea13b81a0b70cfacdec0ca",
            "rtmr2": "8a4fe048fea22663152ef128853caa5c033cbe66baf32ba1ff7f6b1afc1624c279f50a4cbc522a735ca6f69551e61ef2",
            "rtmr3": "561c1b02351cd6f7c803dd36bc95ba25463aa025ce7761156260c9131a5d7c03aeccc10e12160ec3205bb2876a203a7f",
            "event_log": [
              {
                "imr": 0,
                "event_type": 2147483659_u64,
                "digest": "0e35f1b315ba6c912cf791e5c79dd9d3a2b8704516aa27d4e5aa78fb09ede04aef2bbd02ac7a8734c48562b9c26ba35d",
                "event": "",
                "event_payload": "095464785461626c65000100000000000000af96bb93f2b9b84e9462e0ba745642360090800000000000"
              },
              {
                "imr": 0,
                "event_type": 2147483658_u64,
                "digest": "344bc51c980ba621aaa00da3ed7436f7d6e549197dfe699515dfa2c6583d95e6412af21c097d473155875ffd561d6790",
                "event": "",
                "event_payload": "2946762858585858585858582d585858582d585858582d585858582d58585858585858585858585829000000c0ff000000000040080000000000"
              },
              {
                "imr": 0,
                "event_type": 2147483649_u64,
                "digest": "9dc3a1f80bcec915391dcda5ffbb15e7419f77eab462bbf72b42166fb70d50325e37b36f93537a863769bcf9bedae6fb",
                "event": "",
                "event_payload": "61dfe48bca93d211aa0d00e098032b8c0a00000000000000000000000000000053006500630075007200650042006f006f007400"
              },
              {
                "imr": 0,
                "event_type": 2147483649_u64,
                "digest": "6f2e3cbc14f9def86980f5f66fd85e99d63e69a73014ed8a5633ce56eca5b64b692108c56110e22acadcef58c3250f1b",
                "event": "",
                "event_payload": "61dfe48bca93d211aa0d00e098032b8c0200000000000000000000000000000050004b00"
              },
              {
                "imr": 0,
                "event_type": 2147483649_u64,
                "digest": "d607c0efb41c0d757d69bca0615c3a9ac0b1db06c557d992e906c6b7dee40e0e031640c7bfd7bcd35844ef9edeadc6f9",
                "event": "",
                "event_payload": "61dfe48bca93d211aa0d00e098032b8c030000000000000000000000000000004b0045004b00"
              },
              {
                "imr": 0,
                "event_type": 2147483649_u64,
                "digest": "08a74f8963b337acb6c93682f934496373679dd26af1089cb4eaf0c30cf260a12e814856385ab8843e56a9acea19e127",
                "event": "",
                "event_payload": "cbb219d73a3d9645a3bcdad00e67656f0200000000000000000000000000000064006200"
              },
              {
                "imr": 0,
                "event_type": 2147483649_u64,
                "digest": "18cc6e01f0c6ea99aa23f8a280423e94ad81d96d0aeb5180504fc0f7a40cb3619dd39bd6a95ec1680a86ed6ab0f9828d",
                "event": "",
                "event_payload": "cbb219d73a3d9645a3bcdad00e67656f03000000000000000000000000000000640062007800"
              },
              {
                "imr": 0,
                "event_type": 4,
                "digest": "394341b7182cd227c5c6b07ef8000cdfd86136c4292b8e576573ad7ed9ae41019f5818b4b971c9effc60e1ad9f1289f0",
                "event": "",
                "event_payload": "00000000"
              },
              {
                "imr": 0,
                "event_type": 10,
                "digest": "68cd79315e70aecd4afe7c1b23a5ed7b3b8e51a477e1739f111b3156def86bbc56ebf239dcd4591bc7a9fff90023f481",
                "event": "",
                "event_payload": "414350492044415441"
              },
              {
                "imr": 0,
                "event_type": 10,
                "digest": "6bc203b3843388cc4918459c3f5c6d1300a796fb594781b7ecfaa3ae7456975f095bfcc1156c9f2d25e8b8bc1b520f66",
                "event": "",
                "event_payload": "414350492044415441"
              },
              {
                "imr": 0,
                "event_type": 10,
                "digest": "ec9e8622a100c399d71062a945f95d8e4cdb7294e8b1c6d17a6a8d37b5084444000a78b007ef533f290243421256d25c",
                "event": "",
                "event_payload": "414350492044415441"
              },
              {
                "imr": 1,
                "event_type": 2147483651_u64,
                "digest": "f51c5215e1ae1e5202fb0a710248e13c2bf2824b7f0b2a1675f63e9fd37befb93fbb97a4f8630879168b76aee3b198e2",
                "event": "",
                "event_payload": "1860447b0000000000f4b2000000000000000000000000002a000000000000000403140072f728144ab61e44b8c39ebdd7f893c7040412006b00650072006e0065006c0000007fff0400"
              },
              {
                "imr": 0,
                "event_type": 2147483650_u64,
                "digest": "1dd6f7b457ad880d840d41c961283bab688e94e4b59359ea45686581e90feccea3c624b1226113f824f315eb60ae0a7c",
                "event": "",
                "event_payload": "61dfe48bca93d211aa0d00e098032b8c0900000000000000020000000000000042006f006f0074004f0072006400650072000000"
              },
              {
                "imr": 0,
                "event_type": 2147483650_u64,
                "digest": "23ada07f5261f12f34a0bd8e46760962d6b4d576a416f1fea1c64bc656b1d28eacf7047ae6e967c58fd2a98bfa74c298",
                "event": "",
                "event_payload": "61dfe48bca93d211aa0d00e098032b8c08000000000000003e0000000000000042006f006f0074003000300030003000090100002c0055006900410070007000000004071400c9bdb87cebf8344faaea3ee4af6516a10406140021aa2c4614760345836e8ab6f46623317fff0400"
              },
              {
                "imr": 1,
                "event_type": 2147483655_u64,
                "digest": "77a0dab2312b4e1e57a84d865a21e5b2ee8d677a21012ada819d0a98988078d3d740f6346bfe0abaa938ca20439a8d71",
                "event": "",
                "event_payload": "43616c6c696e6720454649204170706c69636174696f6e2066726f6d20426f6f74204f7074696f6e"
              },
              {
                "imr": 1,
                "event_type": 4,
                "digest": "394341b7182cd227c5c6b07ef8000cdfd86136c4292b8e576573ad7ed9ae41019f5818b4b971c9effc60e1ad9f1289f0",
                "event": "",
                "event_payload": "00000000"
              },
              {
                "imr": 2,
                "event_type": 6,
                "digest": "a68ac6d65dd62f392826c2ae44f6846363ced3418c96574b3e168de9205c8553b8198c3b9d206bc432d70a923c25b098",
                "event": "",
                "event_payload": "ed223b8f1a0000004c4f414445445f494d4147453a3a4c6f61644f7074696f6e7300"
              },
              {
                "imr": 2,
                "event_type": 6,
                "digest": "21a1d39f7395e15c35b91dacf14714cf2e9ead77e69f076ce164798272c1838312b2d82b3307b91929a4d7dbc6f1e48b",
                "event": "",
                "event_payload": "ec223b8f0d0000004c696e757820696e6974726400"
              },
              {
                "imr": 1,
                "event_type": 2147483655_u64,
                "digest": "214b0bef1379756011344877743fdc2a5382bac6e70362d624ccf3f654407c1b4badf7d8f9295dd3dabdef65b27677e0",
                "event": "",
                "event_payload": "4578697420426f6f7420536572766963657320496e766f636174696f6e"
              },
              {
                "imr": 1,
                "event_type": 2147483655_u64,
                "digest": "0a2e01c85deae718a530ad8c6d20a84009babe6c8989269e950d8cf440c6e997695e64d455c4174a652cd080f6230b74",
                "event": "",
                "event_payload": "4578697420426f6f742053657276696365732052657475726e656420776974682053756363657373"
              },
              {
                "imr": 3,
                "event_type": 134217729,
                "digest": "738ae348dbf674b3399300c0b9416c203e9b645c6ffee233035d09003cccad12f71becc805ad8d97575bc790c6819216",
                "event": "rootfs-hash",
                "event_payload": "4a89dadfa8c6be6d312beb51e24ef5bd4b3aeb695f11f4e2ff9c87eac907389b"
              },
              {
                "imr": 3,
                "event_type": 134217729,
                "digest": "8ecf784c418ff83b7c8d67adfa7b6c13c93766e0356fd915d038133a170fa09b42ef91aad28642adcee58a0c8a542e7d",
                "event": "app-id",
                "event_payload": "9f91439ecacc4f8845a9cd81cc141256d5e1bce3"
              },
              {
                "imr": 3,
                "event_type": 134217729,
                "digest": "2ce008f8d73c3d9d6d0a176828da3ae21eea3f748f61d655d142416ac82c19a23eaf239a3654fac97e09588264c439ff",
                "event": "compose-hash",
                "event_payload": "9f91439ecacc4f8845a9cd81cc141256d5e1bce3ab2c1533c842402d1a306ff0"
              },
              {
                "imr": 3,
                "event_type": 134217729,
                "digest": "5b6a576d1da40f04179ad469e00f90a1c0044bc9e8472d0da2776acb108dc98a73560d42cea6b8b763eb4a0e6d4d82d5",
                "event": "ca-cert-hash",
                "event_payload": "d2d9c7c29e3f18e69cba87438cef21eea084c2110858230cd39c5decc629a958"
              },
              {
                "imr": 3,
                "event_type": 134217729,
                "digest": "5243ab8e3d13d9b22168b43c901b4559c534d9dafa434bba36e7b86756cdedb58e6cbc9a41473de3e117768f83e2f2cc",
                "event": "instance-id",
                "event_payload": "f96d8cde26eacea3712d3a4ffc693c4942701e08"
              }
            ],
            "app_compose": "{\"bash_script\":null,\"docker_compose_file\":\"version: '4.0'\\nservices:\\n    web:\\n        platform: linux/amd64 # Explicitly set for TDX\\n        image: mattdlockyer/based-agent-test:latest@sha256:67b7d2074ac0b6621035b9938f896ed2367707d8384e1e3baa4c0c4c39d05da7\\n        container_name: web\\n        ports:\\n            - '3000:3000'\\n        volumes:\\n            - /var/run/tappd.sock:/var/run/tappd.sock\\n        restart: always\\n\",\"docker_config\":{\"password\":\"\",\"registry\":null,\"username\":\"\"},\"features\":[\"kms\",\"tproxy-net\"],\"kms_enabled\":true,\"manifest_version\":2,\"name\":\"test\",\"pre_launch_script\":\"\\n#!/bin/bash\\necho \\\"----------------------------------------------\\\"\\necho \\\"Running Phala Cloud Pre-Launch Script v0.0.1\\\"\\necho \\\"----------------------------------------------\\\"\\nset -e\\n\\n# Function: Perform Docker cleanup\\nperform_cleanup() {\\n    echo \\\"Pruning unused images\\\"\\n    docker image prune -af\\n    echo \\\"Pruning unused volumes\\\"\\n    docker volume prune -f\\n}\\n\\n# Function: Check Docker login status without exposing credentials\\ncheck_docker_login() {\\n    # Try to verify login status without exposing credentials\\n    if docker info 2>/dev/null | grep -q \\\"Username\\\"; then\\n        return 0\\n    else\\n        return 1\\n    fi\\n}\\n\\n# Function: Check AWS ECR login status\\ncheck_ecr_login() {\\n    # Check if we can access the registry without exposing credentials\\n    if aws ecr get-authorization-token --region $DSTACK_AWS_REGION &>/dev/null; then\\n        return 0\\n    else\\n        return 1\\n    fi\\n}\\n\\n# Main logic starts here\\necho \\\"Starting login process...\\\"\\n\\n# Check if Docker credentials exist\\nif [[ -n \\\"$DSTACK_DOCKER_USERNAME\\\" && -n \\\"$DSTACK_DOCKER_PASSWORD\\\" ]]; then\\n    echo \\\"Docker credentials found\\\"\\n    \\n    # Check if already logged in\\n    if check_docker_login; then\\n        echo \\\"Already logged in to Docker registry\\\"\\n    else\\n        echo \\\"Logging in to Docker registry...\\\"\\n        # Login without exposing password in process list\\n        echo \\\"$DSTACK_DOCKER_PASSWORD\\\" | docker login -u \\\"$DSTACK_DOCKER_USERNAME\\\" --password-stdin\\n        \\n        if [ $? -eq 0 ]; then\\n            echo \\\"Docker login successful\\\"\\n        else\\n            echo \\\"Docker login failed\\\"\\n            exit 1\\n        fi\\n    fi\\n# Check if AWS ECR credentials exist\\nelif [[ -n \\\"$DSTACK_AWS_ACCESS_KEY_ID\\\" && -n \\\"$DSTACK_AWS_SECRET_ACCESS_KEY\\\" && -n \\\"$DSTACK_AWS_REGION\\\" && -n \\\"$DSTACK_AWS_ECR_REGISTRY\\\" ]]; then\\n    echo \\\"AWS ECR credentials found\\\"\\n    \\n    # Check if AWS CLI is installed\\n    if ! command -v aws &> /dev/null; then\\n        echo \\\"AWS CLI not installed, installing...\\\"\\n        curl \\\"https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip\\\" -o \\\"awscliv2.zip\\\"\\n        echo \\\"6ff031a26df7daebbfa3ccddc9af1450 awscliv2.zip\\\" | md5sum -c\\n        if [ $? -ne 0 ]; then\\n            echo \\\"MD5 checksum failed\\\"\\n            exit 1\\n        fi\\n        unzip awscliv2.zip &> /dev/null\\n        ./aws/install\\n        \\n        # Clean up installation files\\n        rm -rf awscliv2.zip aws\\n    else\\n        echo \\\"AWS CLI is already installed: $(which aws)\\\"\\n    fi\\n    \\n    # Configure AWS CLI\\n    aws configure set aws_access_key_id \\\"$DSTACK_AWS_ACCESS_KEY_ID\\\"\\n    aws configure set aws_secret_access_key \\\"$DSTACK_AWS_SECRET_ACCESS_KEY\\\"\\n    aws configure set default.region $DSTACK_AWS_REGION\\n    echo \\\"Logging in to AWS ECR...\\\"\\n    aws ecr get-login-password --region $DSTACK_AWS_REGION | docker login --username AWS --password-stdin \\\"$DSTACK_AWS_ECR_REGISTRY\\\"\\n    if [ $? -eq 0 ]; then\\n        echo \\\"AWS ECR login successful\\\"\\n    else\\n        echo \\\"AWS ECR login failed\\\"\\n        exit 1\\n    fi\\nfi\\n\\nperform_cleanup\\n\\necho \\\"----------------------------------------------\\\"\\necho \\\"Script execution completed\\\"\\necho \\\"----------------------------------------------\\\"\\n\",\"public_logs\":true,\"public_sysinfo\":true,\"runner\":\"docker-compose\",\"salt\":\"6412e8ad-2621-4166-8fdb-8a01df042e15\",\"tproxy_enabled\":true,\"version\":\"1.0.0\"}"
          }
    );

    let event_log = tcb_info["event_log"].as_array().unwrap();
    let quote_collateral = json!({"tcb_info_issuer_chain":"-----BEGIN CERTIFICATE-----\nMIICizCCAjKgAwIBAgIUfjiC1ftVKUpASY5FhAPpFJG99FUwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNTAxMFoXDTI1MDUyMTEwNTAxMFowbDEeMBwG\nA1UEAwwVSW50ZWwgU0dYIFRDQiBTaWduaW5nMRowGAYDVQQKDBFJbnRlbCBDb3Jw\nb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYD\nVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABENFG8xzydWRfK92bmGv\nP+mAh91PEyV7Jh6FGJd5ndE9aBH7R3E4A7ubrlh/zN3C4xvpoouGlirMba+W2lju\nypajgbUwgbIwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqwwUgYDVR0f\nBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNlcnZpY2Vz\nLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5kZXIwHQYDVR0OBBYEFH44gtX7VSlK\nQEmORYQD6RSRvfRVMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMAoGCCqG\nSM49BAMCA0cAMEQCIB9C8wOAN/ImxDtGACV246KcqjagZOR0kyctyBrsGGJVAiAj\nftbrNGsGU8YH211dRiYNoPPu19Zp/ze8JmhujB0oBw==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG\nA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\naW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\nAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7\n1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB\nuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ\nMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\nZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV\nUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\nKoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg\nAiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=\n-----END CERTIFICATE-----\n","tcb_info":"{\"id\":\"TDX\",\"version\":3,\"issueDate\":\"2025-03-11T00:36:15Z\",\"nextUpdate\":\"2025-04-10T00:36:15Z\",\"fmspc\":\"20a06f000000\",\"pceId\":\"0000\",\"tcbType\":0,\"tcbEvaluationDataNumber\":17,\"tdxModule\":{\"mrsigner\":\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"attributes\":\"0000000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\"},\"tdxModuleIdentities\":[{\"id\":\"TDX_03\",\"mrsigner\":\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"attributes\":\"0000000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\",\"tcbLevels\":[{\"tcb\":{\"isvsvn\":3},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"}]},{\"id\":\"TDX_01\",\"mrsigner\":\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"attributes\":\"0000000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\",\"tcbLevels\":[{\"tcb\":{\"isvsvn\":4},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"},{\"tcb\":{\"isvsvn\":2},\"tcbDate\":\"2023-08-09T00:00:00Z\",\"tcbStatus\":\"OutOfDate\"}]}],\"tcbLevels\":[{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":2,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":255,\"category\":\"BIOS\"},{\"svn\":0},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"SEAMLDR ACM\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":13,\"tdxtcbcomponents\":[{\"svn\":5,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":0,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TDX Late Microcode Update\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}]},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"},{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":2,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":255,\"category\":\"BIOS\"},{\"svn\":0},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"SEAMLDR ACM\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":5,\"tdxtcbcomponents\":[{\"svn\":5,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":0,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TDX Late Microcode Update\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}]},\"tcbDate\":\"2018-01-04T00:00:00Z\",\"tcbStatus\":\"OutOfDate\"}]}","tcb_info_signature":"dff1380a12d533bff4ad7f69fd0355ad97ff034b42c8269e26e40e3d585dffff3e55bf21f8cda481d3c163fafcd4eab11c8818ba6aa7553ba6866bce06b56a95","qe_identity_issuer_chain":"-----BEGIN CERTIFICATE-----\nMIICizCCAjKgAwIBAgIUfjiC1ftVKUpASY5FhAPpFJG99FUwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNTAxMFoXDTI1MDUyMTEwNTAxMFowbDEeMBwG\nA1UEAwwVSW50ZWwgU0dYIFRDQiBTaWduaW5nMRowGAYDVQQKDBFJbnRlbCBDb3Jw\nb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYD\nVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABENFG8xzydWRfK92bmGv\nP+mAh91PEyV7Jh6FGJd5ndE9aBH7R3E4A7ubrlh/zN3C4xvpoouGlirMba+W2lju\nypajgbUwgbIwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqwwUgYDVR0f\nBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNlcnZpY2Vz\nLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5kZXIwHQYDVR0OBBYEFH44gtX7VSlK\nQEmORYQD6RSRvfRVMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMAoGCCqG\nSM49BAMCA0cAMEQCIB9C8wOAN/ImxDtGACV246KcqjagZOR0kyctyBrsGGJVAiAj\nftbrNGsGU8YH211dRiYNoPPu19Zp/ze8JmhujB0oBw==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG\nA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\naW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\nAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7\n1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB\nuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ\nMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\nZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV\nUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\nKoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg\nAiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=\n-----END CERTIFICATE-----\n","qe_identity":"{\"id\":\"TD_QE\",\"version\":2,\"issueDate\":\"2025-03-10T23:38:16Z\",\"nextUpdate\":\"2025-04-09T23:38:16Z\",\"tcbEvaluationDataNumber\":17,\"miscselect\":\"00000000\",\"miscselectMask\":\"FFFFFFFF\",\"attributes\":\"11000000000000000000000000000000\",\"attributesMask\":\"FBFFFFFFFFFFFFFF0000000000000000\",\"mrsigner\":\"DC9E2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8C5\",\"isvprodid\":2,\"tcbLevels\":[{\"tcb\":{\"isvsvn\":4},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"}]}","qe_identity_signature":"920d5f18df6da142a667caf71844d45dfd4de3e3b14f846bae92a3e52a9c765d855b9a8b4b54307dd3feae30f28f09888a3200c29584d7c50d42f85275afe6cc"});
    let raw_quote_collateral = quote_collateral.to_string();
    let collateral = get_collateral(raw_quote_collateral);
    let quote_hex = "040002008100000000000000939a7233f79c4ca9940a0db3957f0607ac666ed993e70e31ff5f5a8a2c743b220000000007010300000000000000000000000000c51e5cb16c461fe29b60394984755325ecd05a9a7a8fb3a116f1c3cf0aca4b0eb9edefb9b404deeaee4b7d454372d17a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000702000000000000c68518a0ebb42136c12b2275164f8c72f25fa9a34392228687ed6e9caeb9c0f1dbd895e9cf475121c029dc47e70e91fd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000085e0855a6384fa1c8a6ab36d0dcbfaa11a5753e5a070c08218ae5fe872fcb86967fd2449c29e22e59dc9fec998cb65474a7db64a609c77e85f603c23e9a9fd03bfd9e6b52ce527f774a598e66d58386026cea79b2aea13b81a0b70cfacdec0ca8a4fe048fea22663152ef128853caa5c033cbe66baf32ba1ff7f6b1afc1624c279f50a4cbc522a735ca6f69551e61ef2561c1b02351cd6f7c803dd36bc95ba25463aa025ce7761156260c9131a5d7c03aeccc10e12160ec3205bb2876a203a7fb81447910d62fd92897d68b1f51d54fb75dfe2aeba3a97a879cba59a771fc522d88046cc26b407d723f726fae17c3e5a50529d0b6c2b991d027f06a9b430d43ecc1000003bdd12b68ee3cfc93a1758479840b6f8734c2439106d8f0faa50ac919d86ea101c002c41d262670ad84afb8f9ee35c7abbb72dcc01bbc3e3a3773672d665005ee6bcb0c5f4b03f0563c797747f7ddd25d92d4f120bee4a829daca986bbc03c155b3d158f6a386bca7ee49ceb3ec31494b792e0cf22fc4e561ddc57156da1b77a0600461000000303070704ff00020000000000000000000000000000000000000000000000000000000000000000000000000000000015000000000000000700000000000000e5a3a7b5d830c2953b98534c6c59a3a34fdc34e933f7f5898f0a85cf08846bca0000000000000000000000000000000000000000000000000000000000000000dc9e2a7c6f948f17474e34a7fc43ed030f7c1563f1babddf6340c82e0e54a8c5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005d2eb8ae211693884eadaea0be0392c5532c7ff55429e4696c84954444d62ed600000000000000000000000000000000000000000000000000000000000000004f1cd2dde7dd5d4a9a495815f3ac76c56a77a9e06a5279a8c8550b54cf2d7287a630c3b9aefb94b1b6e8491eba4b43baa811c8f44167eb7d9ca933678ea64f5b2000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f05005e0e00002d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d49494538544343424a656741774942416749554439426b736e734170713045567861464a59785a56794f6774664d77436759494b6f5a497a6a3045417749770a634445694d434147413155454177775a535735305a577767553064594946424453794251624746305a6d397962534244515445614d42674741315545436777520a535735305a577767513239796347397959585270623234784644415342674e564241634d43314e68626e526849454e7359584a684d51737743515944565151490a44414a445154454c4d416b474131554542684d4356564d774868634e4d6a55774d6a41334d5463774f4441325768634e4d7a49774d6a41334d5463774f4441320a576a42774d534977494159445651514444426c4a626e526c624342545231676755454e4c49454e6c636e52705a6d6c6a5958526c4d526f77474159445651514b0a4442464a626e526c6243424462334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e560a4241674d416b4e424d517377435159445651514745774a56557a425a4d424d4742797147534d34394167454743437147534d34394177454841304941424853770a3977506a72554532734f4a644c5653415434686565414a572b31796c6473615556696b5a4c485832506235777374326a79697539414f5865576a7a6a6d585a4c0a4343742b457858716f53394e45476c6b52724b6a67674d4e4d4949444354416642674e5648534d4547444157674253566231334e765276683655424a796454300a4d383442567776655644427242674e56485238455a4442694d47436758714263686c706f64485277637a6f764c32467761533530636e567a6447566b633256790a646d6c6a5a584d75615735305a577775593239744c334e6e6543396a5a584a3061575a7059324630615739754c3359304c33426a61324e796244396a595431770a624746305a6d397962535a6c626d4e765a476c755a7a316b5a584977485159445652304f42425945464d6a464e59626f7464634b636859487258467966774b460a774e534d4d41344741315564447745422f775145417749477744414d42674e5648524d4241663845416a41414d4949434f67594a4b6f5a496876684e415130420a424949434b7a4343416963774867594b4b6f5a496876684e41513042415151514134346b35686a336951797044574873756f5a474144434341575147436971470a534962345451454e41514977676746554d42414743797147534962345451454e41514942416745434d42414743797147534962345451454e41514943416745430a4d42414743797147534962345451454e41514944416745434d42414743797147534962345451454e41514945416745434d42414743797147534962345451454e0a41514946416745434d42454743797147534962345451454e41514947416749412f7a415142677371686b69472b453042445145434277494241444151426773710a686b69472b4530424451454343414942416a415142677371686b69472b45304244514543435149424144415142677371686b69472b45304244514543436749420a4144415142677371686b69472b45304244514543437749424144415142677371686b69472b45304244514543444149424144415142677371686b69472b4530420a44514543445149424144415142677371686b69472b45304244514543446749424144415142677371686b69472b453042445145434477494241444151426773710a686b69472b45304244514543454149424144415142677371686b69472b45304244514543455149424454416642677371686b69472b45304244514543456751510a4167494341674c2f4141494141414141414141414144415142676f71686b69472b45304244514544424149414144415542676f71686b69472b453042445145450a424159676f473841414141774477594b4b6f5a496876684e4151304242516f424154416542676f71686b69472b453042445145474242414b496f456755387a650a486d2b49596f7a686c337a314d45514743697147534962345451454e415163774e6a415142677371686b69472b45304244514548415145422f7a4151426773710a686b69472b45304244514548416745422f7a415142677371686b69472b45304244514548417745422f7a414b42676771686b6a4f5051514441674e49414442460a4169417362735a44796d2f72455a30476c454c62442f6e64755061536a485341746e5871567453313047486255774968414d585666784b334b666f4b675131660a4578397478765331314362363662323467424344523963477942562b0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436c6a4343416a32674177494241674956414a567658633239472b487051456e4a3150517a7a674658433935554d416f4743437147534d343942414d430a4d476778476a415942674e5642414d4d45556c756447567349464e48574342536232393049454e424d526f77474159445651514b4442464a626e526c624342440a62334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e564241674d416b4e424d5173770a435159445651514745774a56557a4165467730784f4441314d6a45784d4455774d5442614677307a4d7a41314d6a45784d4455774d5442614d484178496a41670a42674e5642414d4d47556c756447567349464e4857434251513073675547786864475a76636d306751304578476a415942674e5642416f4d45556c75644756730a49454e76636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b474131554543417743513045780a437a414a42674e5642415954416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741454e53422f377432316c58534f0a3243757a7078773734654a423732457944476757357258437478327456544c7136684b6b367a2b5569525a436e71523770734f766771466553786c6d546c4a6c0a65546d693257597a33714f42757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f536347724442530a42674e5648523845537a424a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b633256790a646d6c6a5a584d75615735305a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e5648513445466751556c5739640a7a62306234656c4153636e553944504f4156634c336c517744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159420a4166384341514177436759494b6f5a497a6a30454177494452774177524149675873566b6930772b6936565947573355462f32327561586530594a446a3155650a6e412b546a44316169356343494359623153416d4435786b66545670766f34556f79695359787244574c6d5552344349394e4b7966504e2b0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436a7a4343416a53674177494241674955496d554d316c71644e496e7a6737535655723951477a6b6e42717777436759494b6f5a497a6a3045417749770a614445614d4267474131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e760a636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a0a42674e5642415954416c56544d423458445445344d4455794d5445774e4455784d466f58445451354d54497a4d54497a4e546b314f566f77614445614d4267470a4131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e76636e4276636d46300a615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a42674e56424159540a416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414543366e45774d4449595a4f6a2f69505773437a61454b69370a314f694f534c52466857476a626e42564a66566e6b59347533496a6b4459594c304d784f346d717379596a6c42616c54565978465032734a424b357a6c4b4f420a757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f5363477244425342674e5648523845537a424a0a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b63325679646d6c6a5a584d75615735300a5a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e564851344546675155496d554d316c71644e496e7a673753560a55723951477a6b6e4271777744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159424166384341514577436759490a4b6f5a497a6a3045417749445351417752674968414f572f35516b522b533943695344634e6f6f774c7550524c735747662f59693747535839344267775477670a41694541344a306c72486f4d732b586f356f2f7358364f39515778485241765a55474f6452513763767152586171493d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let quote = decode(quote_hex).unwrap();
    // test against quote bin
    // let quote = std::fs::read("../samples/4.bin").expect("quote is not found");
    // println!("{:?}", collateral);

    let now = 1747699200; // 20 May 2025, 00:00:00 UTC

    // get compose hash from events
    let expected_compose_hash = event_log
        .iter()
        .find(|e| e["event"].as_str().unwrap() == "compose-hash")
        .unwrap()["digest"]
        .as_str()
        .unwrap();

    // verified report with rtmrs
    let result = verify::verify(&quote, &collateral, now).unwrap();
    let rtmr3 = encode(result.report.as_td10().unwrap().rt_mr3);

    // replay the rtmr3 and compose hash
    let replayed_rtmr3 = replay_rtmr(event_log.to_owned(), 3);
    let replayed_compose_hash: String =
        replay_app_compose(tcb_info["app_compose"].as_str().unwrap());

    // compose hash match expected
    assert!(replayed_compose_hash == expected_compose_hash);
    // event with compose hash matches report rtmr3
    assert!(replayed_rtmr3 == rtmr3);

    println!("replayed_rtmr3 {:?}", replayed_rtmr3);
    println!("replayed_compose_hash {:?}", replayed_compose_hash);

    let codehash = verify_codehash(tcb_info.to_string(), rtmr3);

    println!("codehash {:?}", codehash);
}
