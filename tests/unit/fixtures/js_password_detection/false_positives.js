// Strings containing credential-adjacent words but NOT assigned to a
// credential-named variable. Detector should NOT fire on any of these.

// Logger / function-call arguments — the brass-seo cases.
console.error('Password reset error:', err);
console.warn('Failed to load secret: undefined');
console.log('API key validation failed for user');
describe('Password validation rules', () => {});

// Sentence-like assigned values that don't look like credentials.
const errorMessage = "Password must be at least 8 characters";
const helpText = "Enter your secret access key in the API key field";
const docComment = "See the docs for how to rotate the JWT secret";

// process.env references / placeholders / templates.
const password = process.env.PASSWORD;
const apiKey = "${API_KEY}";
const secret = "your_secret_here";
const token = "<your-token>";
const example = "change_me";

// Short values — under credential length threshold.
const password2 = "hi";

// Identifier name doesn't match credential pattern.
const monkey = "abcd1234!@#$";
const description = "abcd1234!@#$";
