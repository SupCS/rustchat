mod db;
mod handlers;
mod routes;

use dotenvy::dotenv;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv().ok();

    // Підключення до бази даних
    let db = db::connect_to_db().await?;

    // Реєстрація маршрутів
    let register = routes::register_routes(db);

    // Запуск сервера
    warp::serve(register).run(([127, 0, 0, 1], 3030)).await;

    Ok(())
}
