use dotenvy::dotenv;
use mongodb::{options::ClientOptions, Client};
use std::env;

#[tokio::main]
async fn main() -> mongodb::error::Result<()> {
    // Завантажуємо змінні середовища з .env файлу
    dotenv().ok();

    // Отримуємо URI з середовища
    let uri = env::var("MONGODB_URI").expect("Змінна середовища MONGODB_URI не встановлена");

    // Налаштування клієнта MongoDB
    let options = ClientOptions::parse(&uri).await?;
    let client = Client::with_options(options)?;

    // Перевірка підключення
    println!("Підключення до MongoDB успішне!");

    // Отримання доступу до бази даних
    let db = client.database("chat_app");
    println!("Використовується база даних: {}", db.name());

    Ok(())
}
