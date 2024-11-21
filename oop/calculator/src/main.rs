// Define a trait for basic calculator operations
trait CalculatorOperations {
    fn add(&self, a: f64, b: f64) -> f64;
    fn subtract(&self, a: f64, b: f64) -> f64;
    fn multiply(&self, a: f64, b: f64) -> f64;
    fn divide(&self, a: f64, b: f64) -> Result<f64, String>;
}

// Define a struct for the Calculator
struct Calculator;

// Implement the trait for the Calculator
impl CalculatorOperations for Calculator {
    fn add(&self, a: f64, b: f64) -> f64 {
        a + b
    }

    fn subtract(&self, a: f64, b: f64) -> f64 {
        a - b
    }

    fn multiply(&self, a: f64, b: f64) -> f64 {
        a * b
    }

    fn divide(&self, a: f64, b: f64) -> Result<f64, String> {
        if b != 0.0 {
            Ok(a / b)
        } else {
            Err("Error: Division by zero is not allowed".to_string())
        }
    }
}

fn main() {
    // Create a new instance of Calculator
    let calc = Calculator;

    // Perform operations
    let a = 10.0;
    let b = 2.0;

    println!("Add: {} + {} = {}", a, b, calc.add(a, b));
    println!("Subtract: {} - {} = {}", a, b, calc.subtract(a, b));
    println!("Multiply: {} * {} = {}", a, b, calc.multiply(a, b));

    match calc.divide(a, b) {
        Ok(result) => println!("Divide: {} / {} = {}", a, b, result),
        Err(e) => println!("{}", e),
    }

    // Test division by zero
    match calc.divide(a, 0.0) {
        Ok(result) => println!("Divide: {} / 0 = {}", a, result),
        Err(e) => println!("{}", e),
    }
}
