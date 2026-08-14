-- Runtime financial writers can assemble a DRAFT but cannot directly UPDATE a
-- journal header. Finalization is the only SECURITY DEFINER capability and all
-- invariant triggers execute under its owner. Tables are schema-qualified to
-- prevent search_path substitution.
CREATE OR REPLACE FUNCTION public.finalize_ledger_transaction(target_transaction_id STRING)
RETURNS STRING AS $$
DECLARE
    finalized_transaction_id STRING;
BEGIN
    UPDATE public.ledger_transactions
       SET status='POSTED', posted_at=transaction_timestamp()
     WHERE transaction_id=target_transaction_id AND status='DRAFT'
    RETURNING transaction_id INTO finalized_transaction_id;
    RETURN finalized_transaction_id;
END;
$$ LANGUAGE PLpgSQL SECURITY DEFINER;

REVOKE ALL ON FUNCTION public.finalize_ledger_transaction(STRING) FROM public;
GRANT EXECUTE ON FUNCTION public.finalize_ledger_transaction(STRING) TO ledger_writer;

REVOKE UPDATE ON TABLE ledger_transactions FROM ledger_writer;
GRANT INSERT ON TABLE ledger_transactions TO ledger_writer;
