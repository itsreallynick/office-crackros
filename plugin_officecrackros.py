#!/usr/bin/env python
# OfficeCrackros (substitution cipher detector/decoder) plugin for oledump.py by Nick Carr, while at Mandiant
# 2016/06/01

import re
import string

def deobfuscate(text, key):
    # For every char in the key
    for i in range(len(key)):
        # Remove all instances of that char in the text
        while True:
            found = text.find(key[i])
            # If we still have a char in the text, remove it
            if (found != -1):
                text = text[:found] + text[found+1:];
            # Otherwise, break
            else:
                break;
    # Return unobfuscated string
    return text;

class cOfficeCrackros(cPluginParent):
    macroOnly = True #observed Macros
    name = 'Subsitution cipher detected: OfficeCrackros plugin by Nick Carr'

    def __init__(self, name, stream, options):
        self.streamname = name
        self.stream = stream
        self.options = options
        self.ran = False

    def Analyze(self):
        result = []

        if len(self.streamname) > 1:
            for nbi in re.findall(r'h.{0,3}t.{0,3}t.{0,3}p.{0,7}\:.{0,3}\/.{0,3}\/[^"][^)]*', self.stream):
                # can remove last ^ to get key, but this is more fun
                self.ran = True
                result.append('ENCODED NBI: ' + nbi)

            for obfuscated in re.findall(r'\(\".*\"\,\s\".*\"\)', self.stream):
                # Pattern to match: ("<text, may include special chars>", "<key>")
                self.ran = True
                counter = 0
                for matches in re.split(', "', obfuscated):
                    if (counter %2 == 0):
                        text = re.sub('[()"]', '', matches)
                    else:
                        key = re.sub('[()"]', '', matches)
                        result.append('DECODED STRING: ' + deobfuscate(text, key))
                    counter+=1
        return result

AddPlugin(cOfficeCrackros)