// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use reposnake::object_store::ObjectStore;
use reposnake::s3_object_store::S3ObjectStore;

const BUCKET: &str = "repo-noa-re";
const CONTENT: &[u8] = b"hello world";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let store = S3ObjectStore::from_bucket(BUCKET).await?;
    let mut writer = store.create_writer().await?;
    writer.write_chunk(CONTENT).await?;
    let sha256 = writer.commit().await?;
    let digest = hex::encode(sha256);

    println!("uploaded {} bytes", CONTENT.len());
    println!("bucket: {BUCKET}");
    println!("sha256: {digest}");
    println!("key: objects/{digest}");
    Ok(())
}
