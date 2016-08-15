# OfficeCrackros
##### Crack your macros like the math pros.
This is a substitution cipher detector & decoder plugin for Microsoft Office documents. Essentially, this is Sigpedia for Macros. What I'm trying to say is I think you'll find this helpful if you can navigate all the trolling.

## How To Use It
### 1. download teh scripts
### 2. run against suspect documents
   **Usage:** ```python oledump.py -p plugin_officecrackros <path/to/file.doc>```
### 3. spark like your life depends on it
  * If you found the tool helpful, spark it up like old times
  * Is this helpful enough for Backscatter plugins... probably not? But you decide!

---
## Requirements
* oledump
  * Didier Stevens, who is awesome, created this tool
    * oledump has been included in this repository
    * https://github.com/DidierStevens/DidierStevensSuite/blob/master/oledump.py
  * oledump requires olefile python library: ```easy_install olefile```
* Malicious Microsoft Office Document using encoded macros
  * Specifically: Nymain / UNC622 macros using substitution noise
  * Examples: 
     * 5a09b2970c61353454ecb981f4a37862
     * 5df764298eaf8dd2be0514c3785c846d
     * 6c82d4858d0d5dd4f6139cf44339f337
     * many more!

## To Do List:
* ~~CRUSH IT.~~
* Remove extraneous text in multiple line matches (improve regular expressions)

> **“I Love you, Always Have, Always Will.”** - Zheng Bu
