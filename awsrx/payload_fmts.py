#coding=cp850
# *** START OF MESSAGE FORMAT SPECIFICATIONS FOR NORMAL USERS ***
# Here the format of the binary data is defined. The keys of the FormatSpec dictionary
# come in groups of 5 (5...9, 10...14, and so on) and each group corresponds to the set of
# messages that can be transmitted by a given AWS (summer, winter, diagnostic, ... see below)
# The BinaryTxFormatRevision setting in the logger program need to match with the keys
# of the FormatDict dictionary, so that BinaryTxFormatRevision = 1 corresponds to keys 5...9
# and BinaryTxFormatRevision = 5 to keys 25...29. This is required because the receiving
# end has no way to tell where and what kind of values are encoded in the binary message.
# The possible value types are as follow:
# f = value encoded as 2 bytes base-10 floating point (GFP2)
# l = value encoded as 4 bytes two's complement integer (GLI4)
# t = timestamp as seconds since 1990-01-01 00:00:00 +0000 encoded as GLI4
# g = GPS time encoded as GLI4
# n = GPS latitude encoded as GLI4
# e = GPS latitude encoded as GLI4
# It is also possible to decode any of these in debug mode which adds to the decoded value the 
# raw bytes as characters, as hex and as bit string, in brackets, e.g. an FP2 values of -1600 
# will be written out as -1600(‘ @ = \0\x\E\6 \0\x\40 = 0b11100110 0b01000000) when using 'F' instead 
# of 'f'. Becasue no check is done, a line may get truncated if some special bytes are 
# encountered, probably things like null characters, end of line, escape codes etc. I'm also 
# not sure if/how differently it may work on python 3 or if the data file displays differently 
# based on the locale/character encoding set on the pc.

type_len = {'f': 2, # value encoded as 2 bytes base-10 floating point (GFP2)
            'l': 4, # value encoded as 4 bytes two's complement integer (GLI4)
            't': 4, # timestamp as seconds since 1990-01-01 00:00:00 +0000 encoded as GLI4
            'g': 4, # GPS time encoded as GLI4
            'n': 4, # GPS latitude encoded as GLI4
            'e': 4, # GPS latitude encoded as GLI4
            }

payload_fmt = { #Promice 2009, 2010 
                #5: [13, "tffffffffffff", "Promice 2009 summer message"], #this means: expect 13 values: 1 of type 't' and 12 of type 'f', and display this as "Promice..."
                #6: [39, "tfffffffffffffffffffffffffgneffffffffff", "Promice 2009 summer message (+ instant.)"],
                30: [24, "tfffffffffffffffffffffff", 'CASSANDRA FS2 Summer No EC'],
                32: [24, "tfffffffffffffffffffffff", 'CASSANDRA FS2 Winter No EC'],
                #placeholders for illegal format numbers (reserved for ascii decimal numbers, codes 48 for '0' to 57 for '9')
                48: [0, '', 'placeholder for uncompressed ascii'],
                49: [0, '', 'placeholder for uncompressed ascii'],
                50: [0, '', 'placeholder for uncompressed ascii'],
                51: [0, '', 'placeholder for uncompressed ascii'],
                52: [0, '', 'placeholder for uncompressed ascii'],
                53: [0, '', 'placeholder for uncompressed ascii'],
                54: [0, '', 'placeholder for uncompressed ascii'],
                55: [0, '', 'placeholder for uncompressed ascii'],
                56: [0, '', 'placeholder for uncompressed ascii'],
                57: [0, '', 'placeholder for uncompressed ascii'],

                #THIS IS THE FIRST UNUSED FORMAT (will match BinaryTxFormatRevision = 12 in the logger program)
                # HAVE TO ADD 10!! (stupid bug in the sending side)
                #60: [1, "t", "new summer message"], #
                70: [15, 'tffffffffffffff', 'BHP Summer'],
                72: [15, 'tffffffffffffff', 'BHP Winter'],
                # BinaryTxFormatRevision 14 - CASSANDRA FS 12x EC; t=time; b=batt; c=temp; h=height; number=TDR; e=EC
                #         tbchhh111111222222333333444444555555eeeeeeeeeeee  
                80: [48, 'tfffffffffffffffffffffffffffffffffffffffffffffff', 'FS Summer EC12'],
                82: [36, 'tfffffffffffffffffffffffffffffffffff', 'FS Winter EC12'],
                # BinaryTxFormatRevision 15 - CASSANDRA FS 12x EC
                95: [52, 'tfffffffffffffffffffffffffffffffffffffffffffffffffff', 'FS Summer EC16'],
                97: [36, 'tfffffffffffffffffffffffffffffffffff', 'FS Winter EC16'],
                # BinaryTxFormatRevision 16 - CASSANDRA FS4 (no EC, 4x TDR)
                100: [31, 'tffffffffffffffffffffffffffffff', 'FS Summer noEC'],
                102: [31, 'tffffffffffffffffffffffffffffff', 'FS Winter noEC']
                }