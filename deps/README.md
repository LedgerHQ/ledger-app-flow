## Updating zx-lib

Menu fetaure requires us to change zxlib menu layout. Thus instead of a submodule, we have ledger-zxlib included as a copy. In case you need to update zxlib, this is the list of changes performed. 

- Menu contains new "Show address"/"View address" entries which display address and pubkey according to data saved on slot 0
- Menu changes. Remove "Developed by" and "Website" entries.
- Set MAX_CHARS_PER_VALUE1_LINE to 120
We experienced crashes with certain strings too long. 
- Removed duplicate base58.* files to avoid warnings.

