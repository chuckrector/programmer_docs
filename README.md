# Programmer Docs

"Search all of MSDN in a single text file." is the idea.

Searching MSDN on the internet is slow and annoying.  [Zeal](https://zealdocs.org/) can bring it offline but all of the docsets out there are not very good and are missing many entries.  Zeal's HTML renderer is also very slow and underperforms web browsers.  It also clips documentation in annoying ways.  Microsoft now keeps the MSDN source on GitHub, so it shouldn't be hard to parse it and generate plain text... right?  Many modern editors automatically make links found in plain text interactive and so HTML adds very little additional value.  With everything in a single text file, searching could be done in a tool every programmer is already very familiar with:  their text editor.

# Building

To build, install Visual Studio and run:

```
build.bat
```

# Usage

```sh
build\msdn_entry_to_text <Github .md file>
build\msdn_entry_to_text sample1.md
```

# Notes

* I've currently only tested this on Windows 10.
* I'm exploring the (chaotic) format and have only written a prototype to convert individual files so far.
* The future plan would be to run a script that automatically downloads all of MSDN from GitHub (in a fashion similar to [degit](https://github.com/Rich-Harris/degit)) and automatically convert everything in one go.
* Two `.md` samples are provided which demonstrate some of the variability of the format.