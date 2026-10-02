// In-memory data so the storefront runs without a database in the lab.
const products = [
  { id: 1, name: 'Medovik', price: 180000 },
  { id: 2, name: 'Napoleon', price: 165000 },
  { id: 3, name: 'Tres Leches <mini>', price: 42000 },
];

const reviews = [
  { productId: 1, author: 'Dilnoza', text: 'Best honey cake in Tashkent.' },
];

const users = new Map([
  [1, { id: 1, email: 'customer@example.test', role: 'customer', loyaltyPoints: 120, address: '' }],
  [2, { id: 2, email: 'manager@example.test', role: 'staff', loyaltyPoints: 0, address: '' }],
]);

module.exports = { products, reviews, users };
