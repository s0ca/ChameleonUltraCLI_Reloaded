## Since my PoC has been used in the official CLI client (https://github.com/RfidResearchGroup/ChameleonUltra/pull/66) 
This project doesn't need to live anymore

# ChameleonUltraCLI_Reloaded
An improved version of the official ChamelonUltra CLI client

## Compiling exploit binary
- Create a ``build`` folder into ``src`` and go into it
- Type ``cmake ..`` to generate the makefile
- Type ``make`` and wait for the compilation to finish

## Using the CLI Client
- Install the required libs ``python3 -m pip install -r requirements.txt``
- Launch ``chameleon_cli_main.py`` 
- Profit

[![asciicast](https://asciinema.org/a/601195.png)](https://asciinema.org/a/601195)

### Known bugs
- [ ] Won't catch the KeyboardInterupt 
- [ ] Doesn't update to green USB when connected 
- [ ] No command history
