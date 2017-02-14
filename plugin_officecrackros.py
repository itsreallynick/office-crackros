#!/usr/bin/env python
# OfficeCrackros (substitution cipher detector/decoder) plugin for oledump.py by Nick Carr, while at Mandiant
# 2016/06/01
# Updated 2017/02/13 for Points2Inches (tricky FIN8 macro decoder)

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
    name = 'Sketchy cipher detected: OfficeCrackros plugin by Nick Carr'

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
                # Substition cipher routine (dropchars)
                self.ran = True
                counter = 0
                for matches in re.split(', "', obfuscated):
                    if (counter %2 == 0):
                        text = re.sub('[()"]', '', matches)
                    else:
                        key = re.sub('[()"]', '', matches)
                        result.append('DECODED STRING: ' + deobfuscate(text, key))
                    counter+=1

            for points2inches in re.findall(r'.*\=.*VBA\.Chr\(PointsToInches\(.*\)', self.stream):
                self.ran = True
                p2i_function = re.split(' =',points2inches)[0]  # identifies function name for extraction
    
                for matchingline in re.findall(r'.*' + re.escape(p2i_function) + r'\(.*,.*\)', self.stream): # identifies full lines / context, excludes single item lists
                    p2i_string = ''
                    
                    for encoded in re.findall(re.escape(p2i_function) + r'\([^\)]*\)', matchingline):
                        p2i_array = re.split(p2i_function, encoded)[1]
                        for points in eval(p2i_array):
                            p2i_string += chr(points/72)
                        result.append(re.sub(re.escape(p2i_function) + r'\([^\)]*\)', p2i_string.replace('\\','\\\\'), matchingline).replace('\\\\','\\'))
        return result

AddPlugin(cOfficeCrackros)