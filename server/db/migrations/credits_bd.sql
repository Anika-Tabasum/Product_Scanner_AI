-- Create tables for credits and payments (Bangladesh version)
CREATE TABLE IF NOT EXISTS user_credits (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  balance INTEGER NOT NULL DEFAULT 0,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS credit_packages (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  credits INTEGER NOT NULL,
  price INTEGER NOT NULL,
  description TEXT,
  active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS payment_methods (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  instructions TEXT NOT NULL,
  account_details JSONB NOT NULL,
  active BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS payments (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  package_id INTEGER NOT NULL REFERENCES credit_packages(id),
  payment_method_id INTEGER NOT NULL REFERENCES payment_methods(id),
  amount INTEGER NOT NULL,
  status TEXT NOT NULL, -- 'pending', 'verified', 'rejected'
  transaction_id TEXT, -- bKash/Nagad transaction ID or bank reference
  sender_number TEXT, -- Mobile number for bKash/Nagad
  metadata JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
  verified_at TIMESTAMP WITH TIME ZONE,
  verified_by INTEGER REFERENCES users(id) -- admin who verified the payment
);

CREATE TABLE IF NOT EXISTS credit_usage (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  amount INTEGER NOT NULL,
  type TEXT NOT NULL,
  metadata JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_user_credits_user_id ON user_credits(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_package_id ON payments(package_id);
CREATE INDEX IF NOT EXISTS idx_credit_usage_user_id ON credit_usage(user_id);
CREATE INDEX IF NOT EXISTS idx_credit_usage_type ON credit_usage(type);

-- Insert default credit packages (prices in BDT)
INSERT INTO credit_packages (name, credits, price, description) VALUES
('Starter Pack', 50, 100, '50 credits to get started'),
('Basic Pack', 100, 180, '100 credits with 10% discount'),
('Pro Pack', 500, 800, '500 credits with 20% discount'),
('Enterprise Pack', 1000, 1400, '1000 credits with 30% discount')
ON CONFLICT DO NOTHING;

-- Insert payment methods
INSERT INTO payment_methods (name, instructions, account_details) VALUES
('bKash', 'Send money to our bKash number. Use your order ID as reference.', 
 '{"type": "bkash", "number": "01XXXXXXXXX", "account_type": "Merchant"}'),
('Nagad', 'Send money to our Nagad number. Use your order ID as reference.',
 '{"type": "nagad", "number": "01XXXXXXXXX", "account_type": "Merchant"}'),
('Bank Transfer', 'Transfer to our bank account. Use your order ID as reference in transfer details.',
 '{"bank_name": "Dutch Bangla Bank", "account_name": "Your Company Name", "account_number": "XXXXXXXXXX", "branch": "Main Branch"}')
ON CONFLICT DO NOTHING;
