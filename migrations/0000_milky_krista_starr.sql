CREATE TABLE "ggs_data" (
	"id" serial PRIMARY KEY NOT NULL,
	"original_id" integer NOT NULL,
	"sex" integer NOT NULL,
	"generations" integer NOT NULL,
	"edu_level" integer NOT NULL,
	"age" integer NOT NULL,
	"event_data" jsonb,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "products" (
	"id" serial PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"description" text NOT NULL,
	"brand" text,
	"category" text,
	"identified_text" text,
	"image_url" text,
	"metadata" jsonb,
	"user_id" serial NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" serial PRIMARY KEY NOT NULL,
	"username" text NOT NULL,
	"email" text NOT NULL,
	"password" text NOT NULL,
	"is_verified" boolean DEFAULT false,
	"verification_token" text,
	"reset_token" text,
	"role" text DEFAULT 'user' NOT NULL,
	"profile_picture" text,
	"deleted" boolean DEFAULT false NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "users_username_unique" UNIQUE("username"),
	CONSTRAINT "users_email_unique" UNIQUE("email")
);
--> statement-breakpoint
ALTER TABLE "products" ADD CONSTRAINT "products_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;