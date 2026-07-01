CREATE INDEX "password_reset_account_id_idx" ON "password_reset" USING btree ("account_id");--> statement-breakpoint
CREATE INDEX "session_account_id_idx" ON "session" USING btree ("account_id");