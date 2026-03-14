#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    netshield_api_server::run().await
}
