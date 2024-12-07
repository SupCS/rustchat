use mongodb::{options::ClientOptions, Client, Database};
use std::env;

pub async fn connect_to_db() -> Result<Database, Box<dyn std::error::Error>> {
    let uri = env::var("MONGODB_URI")?;
    let options = ClientOptions::parse(&uri).await?;
    let client = Client::with_options(options)?;
    Ok(client.database("chat_app"))
}
