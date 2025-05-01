-- Remove default constraint first
ALTER TABLE users ALTER COLUMN is_verified DROP DEFAULT;

-- Convert is_verified from text to boolean
ALTER TABLE users 
ALTER COLUMN is_verified TYPE boolean 
USING CASE 
    WHEN is_verified::text = 'true' THEN true
    WHEN is_verified::text = 'false' THEN false
    ELSE false
END;

-- Add back the default constraint
ALTER TABLE users ALTER COLUMN is_verified SET DEFAULT false;
