# Interdiction Hold

**Category:** Web · **Points:** 200 · **Flag:** `CSCTF{ysSyrlHjNXkti0cOTwqy4cfX}`

## What the handout gives you

The challenge provides a live web target running the Meridian Freight Clearance portal for the Orsvane Border Revenue Service:

- `GET /schema` — self-documenting interface detailing routes, approval models, and release controls.
- `GET /embargo-list` — national embargo classification list specifying restricted Harmonized System (HS) tariff codes.
- `GET /consignments` — queue of registered freight consignments and their customs clearance statuses.
- `GET /consignments/{id}` — detailed declaration data including individual cargo line items.
- `GET /consignments/{id}/approval` — cryptographic customs approval record and covered manifest hash.
- `PATCH /consignments/{id}/lineitems/{k}` — post-approval line-item amendment endpoint.
- `POST /consignments/{id}/release` — gateway clearance dispatch endpoint.

## Walkthrough

1. **Locate the embargoed consignment.** Querying `GET /consignments` lists eight active consignments. Seven consignments are in state `PENDING`, while `MFC-5QB8FRE` is flagged with status `HELD`.

2. **Inspect the cargo line items.** Fetching `GET /consignments/MFC-5QB8FRE` displays the cargo manifest:
   - Line item 0: `8409.99` (servo actuators)
   - Line item 1: `9014.80` (signal analysers)
   - Line item 2: `8481.80` (power modules)

   Querying `GET /embargo-list` returns the national embargo list: `["7326.90", "8479.89", "8481.80", "8517.62", "8544.42", "9306.90"]`. The consignment is held because line item 2 declares restricted HS code `8481.80`.

3. **Audit the customs approval model.** Querying `GET /consignments/MFC-5QB8FRE/approval` shows the consignment has already received customs sign-off:

   ```json
   {
     "status": "APPROVED",
     "officer": "CUSTOMS-98",
     "covered_fields": ["ref", "origin", "destination", "declared_value_eur", "carrier", "lineitems[].description", "lineitems[].quantity"],
     "manifest_hash": "853b11aa3b82e445f14e5cc3574e2ff1463d082a046d9ec87873e9288400d93f"
   }
   ```

   The cryptographic signature `manifest_hash` binds only the declared parties, routes, valuations, item descriptions, and item quantities. The HS tariff code (`lineitems[].hs_code`) is omitted from the covered fields list.

4. **Review release requirements.** Under `/schema`, the release rules state:
   - Customs status must be `APPROVED`.
   - The stored `manifest_hash` must match the current hash over the covered fields.
   - No line item may declare an HS code present in `/embargo-list`.
   - Modifying a line item via `PATCH` is permitted with a `justification` string and does not re-open the approval if covered fields are unchanged.

5. **Amend the tariff classification.** Submit a `PATCH` request to line item 2, modifying `hs_code` to a non-embargoed, recognized tariff code (`8409.99`) while keeping `description` and `quantity` unchanged:

   ```bash
   curl -X PATCH http://<instance>/consignments/MFC-5QB8FRE/lineitems/2 \
     -H "Content-Type: application/json" \
     -d '{"hs_code": "8409.99", "justification": "Tariff code reclassification"}'
   ```

   The server responds with HTTP 200: `{"status": "PENDING", "note": "amendment logged; approval not re-opened"}`.

6. **Release the consignment.** Re-checking `/approval` verifies that `current_manifest_hash` remains identical to `manifest_hash`. Send `POST /consignments/MFC-5QB8FRE/release`:

   `curl -X POST http://<instance>/consignments/MFC-5QB8FRE/release`

   Both release controls are satisfied, clearing the interdiction hold and generating the release certificate.

## Answer

The release response contains the clearance certificate:

```json
{
  "status": "RELEASED",
  "certificate": {
    "consignment": "MFC-5QB8FRE",
    "clearance_token": "CSCTF{ysSyrlHjNXkti0cOTwqy4cfX}"
  }
}
```

The flag is:

`CSCTF{ysSyrlHjNXkti0cOTwqy4cfX}`

## Notes

Supplying an invented or malformed code returns `hs_code is not a recognised tariff classification`. Reusing an existing valid tariff code from another line item in the same queue (such as `8409.99`) satisfies the classification check.
