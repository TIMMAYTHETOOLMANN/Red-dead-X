# Instruction / Account Matrix

Build one row per (instruction, account) pair from the IDL/source. This drives lanes A and B.

| Instruction | Account | Expected owner | Expected PDA seeds | Must sign? | Token mint constraint? | Notes |
|-------------|---------|----------------|--------------------|------------|------------------------|-------|
| init_config | config | program | ["config"] | admin | n/a | |
| mint_cvt | payer | system | n/a | yes | n/a | |
| mint_cvt | mint | token program | ["cvt", community] | no | == cvt_mint | |
| burn_hvt | hvt_owner | program | ["hvt", owner] | yes | == hvt_mint | |
| claim_rewards | reward_account | program | ["reward", owner] | yes | n/a | |
| withdraw_fee | treasury | program | ["treasury"] | treasury authority | == fee_mint | |
| set_price | community | program | ["community", owner] | owner | n/a | |

> Replace the example rows above with the real instructions and accounts once the IDL/source is
> pinned. For each account, ask: *is this exactly the account the program thinks it is?*
