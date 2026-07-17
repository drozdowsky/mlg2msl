# mlg2msl
MegaLogViewer .mlg to .msl file converter (.csv also supported)

## Installation
Have python3 installed on your computer.
Download the mlg2msl.py and run it.
That's it, you shouldn't need more.

## Usage
```
  python3 mlg2msl.py re_11.mlg                # -> re_11.msl next to input
  python3 mlg2msl.py *.mlg                    # convert many
  python3 mlg2msl.py re_11.mlg -o out.msl     # explicit output (single input)
  python3 mlg2msl.py re_11.mlg -f csv         # -> re_11.csv (comma-separated,
                                              #    no units row unless --units-row)
```

LLM notice: Created with the help of LLM.
It's less than 200 LOC - easy to audit.
