fn main() {
    let mut i = 0;
    while i < 1000000000 {
        if i % 2 == 0 {
            println!("Even number is ✅: {}", i);
        }
        i += 1;
    }
}
