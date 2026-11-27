-- BookHub: add simulated payment info to checkout_orders
-- Run once on the Neon database (SQL Editor) before using the new checkout.
-- Safe to run more than once.
--
-- Existing orders came from the old checkout (no payment step), so they are
-- back-filled as paid. New orders always set these columns explicitly.

ALTER TABLE checkout_orders
    ADD COLUMN IF NOT EXISTS payment_method VARCHAR(10) NOT NULL DEFAULT 'CARD',
    ADD COLUMN IF NOT EXISTS payment_status VARCHAR(10) NOT NULL DEFAULT 'PAID',
    ADD COLUMN IF NOT EXISTS card_last4    CHAR(4);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'checkout_orders_payment_method_check') THEN
        ALTER TABLE checkout_orders
            ADD CONSTRAINT checkout_orders_payment_method_check
            CHECK (payment_method IN ('COD', 'CARD'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'checkout_orders_payment_status_check') THEN
        ALTER TABLE checkout_orders
            ADD CONSTRAINT checkout_orders_payment_status_check
            CHECK (payment_status IN ('PENDING', 'PAID'));
    END IF;
END $$;
