# Anomalies: current reader (`s19_app/tui/a2l.py` @ e07fb00) against the census lexer, public A2L corpus

Derived data only: file number `n` (see `manifest.tsv`), repo, line number and a structural description. No third-party file content is stored here.
Each class lists at most 8 objects per file and at most 40 rows in this page; the full capped list is `census/anomalies.json` (class, n, line, description). Totals below are object counts over all files (identical-content duplicates counted once).

Oracle = the census lexer (comments, strings, `/begin` tokens; ASAP2 whitespace only), which reads a CHARACTERISTIC address as the 4th header word replaced by the last `ECU_ADDRESS` value of the object itself. A difference is a lead for Inc 11, not yet a proven reader defect.

| class | total objects | rows below |
|---|---|---|
| ADDR_DIFFERENT | 255 | 12 |
| ADDR_READER_NONE_ORACLE_HAS | 729 | 161 |
| BEGIN_NOT_LINE_START | file-level count in rows | 1 |
| CHAR_KIND_DIFFERENT | 657 | 62 |
| DUPLICATE_NAME | 70 | 69 |
| HDR_SHORT | file-level count in rows | 19 |
| KW_NOT_LINE_START | file-level count in rows | 116 |
| LEN_NONE_CHAR_RESOLVABLE_LAYOUT | 17000 | 283 |
| LEN_NONE_MEAS_DATATYPE_DECLARED | 121294 | 414 |
| MEAS_DATATYPE_DIFFERENT | 121299 | 419 |
| NAME_DIFFERENT | 1 | 1 |
| NAME_UNKNOWN_FROM_EMPTY_BEGIN_META | 137243 | 280 |

## ADDR_DIFFERENT

| n | repo | line | structure |
|---|---|---|---|
| 73 | embedconsult/quadesc | 1353 | CHARACTERISTIC reader address 0x0 vs census 0x1000 (header words on the /begin line) |
| 73 | embedconsult/quadesc | 1368 | CHARACTERISTIC reader address 0x0 vs census 0x1002 (header words on the /begin line) |
| 73 | embedconsult/quadesc | 1383 | CHARACTERISTIC reader address 0x0 vs census 0x1008 (header words on the /begin line) |
| 73 | embedconsult/quadesc | 1393 | CHARACTERISTIC reader address 0x0 vs census 0x100c (header words on the /begin line) |
| 73 | embedconsult/quadesc | 1403 | CHARACTERISTIC reader address 0x0 vs census 0x1010 (header words on the /begin line) |
| 73 | embedconsult/quadesc | 1413 | CHARACTERISTIC reader address 0x0 vs census 0x1014 (header words on the /begin line) |
| 73 | embedconsult/quadesc | 1423 | CHARACTERISTIC reader address 0x0 vs census 0x1018 (header words on the /begin line) |
| 73 | embedconsult/quadesc | 1433 | CHARACTERISTIC reader address 0x0 vs census 0x101c (header words on the /begin line) |
| 73 | embedconsult/quadesc | 0 | (+244 more of this class in this file; 252 in total) |
| 124 | Luncher91/A2LParser | 58 | CHARACTERISTIC reader address 0x2710 vs census 0x123 (header words on the /begin line) |
| 125 | Luncher91/A2LParser | 45 | CHARACTERISTIC reader address 0x2710 vs census 0x123 (header words on the /begin line) |
| 126 | Luncher91/A2LParser | 55 | CHARACTERISTIC reader address 0x2710 vs census 0x123 (header words on the /begin line) |

## ADDR_READER_NONE_ORACLE_HAS

| n | repo | line | structure |
|---|---|---|---|
| 13 | AKJ7/CANExplorer | 40 | CHARACTERISTIC reader address None vs census 0x2000 (header words on the /begin line) |
| 13 | AKJ7/CANExplorer | 42 | CHARACTERISTIC reader address None vs census 0x2002 (header words on the /begin line) |
| 13 | AKJ7/CANExplorer | 44 | CHARACTERISTIC reader address None vs census 0x2004 (header words on the /begin line) |
| 14 | vectorgrp/XCPlite | 47 | MEASUREMENT reader address None vs census 0x18 (header words on the /begin line) |
| 14 | vectorgrp/XCPlite | 48 | MEASUREMENT reader address None vs census 0xffe0 (header words on the /begin line) |
| 14 | vectorgrp/XCPlite | 49 | MEASUREMENT reader address None vs census 0x10018 (header words on the /begin line) |
| 14 | vectorgrp/XCPlite | 50 | MEASUREMENT reader address None vs census 0x1ffe0 (header words on the /begin line) |
| 14 | vectorgrp/XCPlite | 51 | MEASUREMENT reader address None vs census 0x20000 (header words on the /begin line) |
| 14 | vectorgrp/XCPlite | 52 | MEASUREMENT reader address None vs census 0x20000 (header words on the /begin line) |
| 14 | vectorgrp/XCPlite | 53 | MEASUREMENT reader address None vs census 0x20000 (header words on the /begin line) |
| 14 | vectorgrp/XCPlite | 54 | MEASUREMENT reader address None vs census 0x20000 (header words on the /begin line) |
| 14 | vectorgrp/XCPlite | 0 | (+2 more of this class in this file; 10 in total) |
| 15 | vectorgrp/XCPlite | 69 | CHARACTERISTIC reader address None vs census 0x80010004 (header words on the /begin line) |
| 15 | vectorgrp/XCPlite | 70 | CHARACTERISTIC reader address None vs census 0x80010000 (header words on the /begin line) |
| 15 | vectorgrp/XCPlite | 71 | CHARACTERISTIC reader address None vs census 0x80010008 (header words on the /begin line) |
| 15 | vectorgrp/XCPlite | 72 | MEASUREMENT reader address None vs census 0x30258 (header words on the /begin line) |
| 15 | vectorgrp/XCPlite | 73 | MEASUREMENT reader address None vs census 0x30260 (header words on the /begin line) |
| 15 | vectorgrp/XCPlite | 74 | MEASUREMENT reader address None vs census 0x10096 (header words on the /begin line) |
| 16 | vectorgrp/XCPlite | 188 | MEASUREMENT reader address None vs census 0xffda (header words on the /begin line) |
| 16 | vectorgrp/XCPlite | 189 | MEASUREMENT reader address None vs census 0xffdc (header words on the /begin line) |
| 16 | vectorgrp/XCPlite | 192 | MEASUREMENT reader address None vs census 0x40ffda (header words on the /begin line) |
| 16 | vectorgrp/XCPlite | 193 | MEASUREMENT reader address None vs census 0x3fca7214 (header words on the /begin line) |
| 16 | vectorgrp/XCPlite | 194 | MEASUREMENT reader address None vs census 0x3fca7210 (header words on the /begin line) |
| 16 | vectorgrp/XCPlite | 195 | MEASUREMENT reader address None vs census 0x3fca720c (header words on the /begin line) |
| 16 | vectorgrp/XCPlite | 196 | MEASUREMENT reader address None vs census 0x3fca7208 (header words on the /begin line) |
| 16 | vectorgrp/XCPlite | 197 | MEASUREMENT reader address None vs census 0x40ffdc (header words on the /begin line) |
| 16 | vectorgrp/XCPlite | 0 | (+14 more of this class in this file; 22 in total) |
| 17 | vectorgrp/XCPlite | 90 | MEASUREMENT reader address None vs census 0x0 (header words on the /begin line) |
| 17 | vectorgrp/XCPlite | 91 | MEASUREMENT reader address None vs census 0x0 (header words on the /begin line) |
| 17 | vectorgrp/XCPlite | 92 | MEASUREMENT reader address None vs census 0x0 (header words on the /begin line) |
| 17 | vectorgrp/XCPlite | 93 | MEASUREMENT reader address None vs census 0x0 (header words on the /begin line) |
| 17 | vectorgrp/XCPlite | 94 | MEASUREMENT reader address None vs census 0x0 (header words on the /begin line) |
| 17 | vectorgrp/XCPlite | 96 | MEASUREMENT reader address None vs census 0x400000 (header words on the /begin line) |
| 17 | vectorgrp/XCPlite | 97 | MEASUREMENT reader address None vs census 0x400000 (header words on the /begin line) |
| 17 | vectorgrp/XCPlite | 98 | MEASUREMENT reader address None vs census 0x400000 (header words on the /begin line) |
| 17 | vectorgrp/XCPlite | 0 | (+1 more of this class in this file; 9 in total) |
| 32 | mrom1/a2lparser | 30 | MEASUREMENT reader address None vs census 0x2dddd (unclassified) |
| 41 | asap2Go/calibrationReader | 3220 | MEASUREMENT reader address None vs census 0x12345 (unclassified) |
| 43 | asap2Go/calibrationReader | 3218 | MEASUREMENT reader address None vs census 0x12345 (unclassified) |
| 44 | vectorgrp/xcp-lite | 149 | MEASUREMENT reader address None vs census 0xb4 (header words on the /begin line) |

(121 more rows in anomalies.json)

## BEGIN_NOT_LINE_START

| n | repo | line | structure |
|---|---|---|---|
| 2 | christoph2/pyA2L | 16 | /begin INSTANCE follows other code on its line |

## CHAR_KIND_DIFFERENT

| n | repo | line | structure |
|---|---|---|---|
| 13 | AKJ7/CANExplorer | 40 | CHARACTERISTIC kind read as None vs census VALUE (9 words on the /begin line) |
| 13 | AKJ7/CANExplorer | 42 | CHARACTERISTIC kind read as None vs census VALUE (9 words on the /begin line) |
| 13 | AKJ7/CANExplorer | 44 | CHARACTERISTIC kind read as None vs census VALUE (9 words on the /begin line) |
| 15 | vectorgrp/XCPlite | 69 | CHARACTERISTIC kind read as None vs census VALUE (9 words on the /begin line) |
| 15 | vectorgrp/XCPlite | 70 | CHARACTERISTIC kind read as None vs census VALUE (11 words on the /begin line) |
| 15 | vectorgrp/XCPlite | 71 | CHARACTERISTIC kind read as None vs census VALUE (9 words on the /begin line) |
| 44 | vectorgrp/xcp-lite | 159 | CHARACTERISTIC kind read as None vs census VALUE (11 words on the /begin line) |
| 44 | vectorgrp/xcp-lite | 160 | CHARACTERISTIC kind read as None vs census VALUE (9 words on the /begin line) |
| 44 | vectorgrp/xcp-lite | 162 | CHARACTERISTIC kind read as None vs census VALUE (11 words on the /begin line) |
| 44 | vectorgrp/xcp-lite | 163 | CHARACTERISTIC kind read as None vs census VALUE (11 words on the /begin line) |
| 45 | vectorgrp/xcp-lite | 181 | CHARACTERISTIC kind read as None vs census VALUE (11 words on the /begin line) |
| 45 | vectorgrp/xcp-lite | 182 | CHARACTERISTIC kind read as None vs census VALUE (11 words on the /begin line) |
| 45 | vectorgrp/xcp-lite | 183 | CHARACTERISTIC kind read as None vs census VALUE (11 words on the /begin line) |
| 45 | vectorgrp/xcp-lite | 184 | CHARACTERISTIC kind read as None vs census VALUE (11 words on the /begin line) |
| 45 | vectorgrp/xcp-lite | 185 | CHARACTERISTIC kind read as None vs census VALUE (11 words on the /begin line) |
| 45 | vectorgrp/xcp-lite | 186 | CHARACTERISTIC kind read as None vs census VALUE (11 words on the /begin line) |
| 45 | vectorgrp/xcp-lite | 187 | CHARACTERISTIC kind read as None vs census VALUE (9 words on the /begin line) |
| 63 | code-2-git/vLenss | 45 | CHARACTERISTIC kind read as None vs census 0x60002000 (1 words on the /begin line) |
| 63 | code-2-git/vLenss | 52 | CHARACTERISTIC kind read as None vs census 0x60003000 (1 words on the /begin line) |
| 71 | embedconsult/quadesc | 23 | CHARACTERISTIC kind read as None vs census VALUE (9 words on the /begin line) |
| 71 | embedconsult/quadesc | 26 | CHARACTERISTIC kind read as None vs census VALUE (9 words on the /begin line) |
| 72 | embedconsult/quadesc | 17 | CHARACTERISTIC kind read as None vs census VALUE (9 words on the /begin line) |
| 72 | embedconsult/quadesc | 20 | CHARACTERISTIC kind read as None vs census VALUE (9 words on the /begin line) |
| 73 | embedconsult/quadesc | 1353 | CHARACTERISTIC kind read as ECU_ADDRESS_EXTENSION vs census VALUE (9 words on the /begin line) |
| 73 | embedconsult/quadesc | 1368 | CHARACTERISTIC kind read as ECU_ADDRESS_EXTENSION vs census VALUE (9 words on the /begin line) |
| 73 | embedconsult/quadesc | 1383 | CHARACTERISTIC kind read as ECU_ADDRESS_EXTENSION vs census VALUE (9 words on the /begin line) |
| 73 | embedconsult/quadesc | 1393 | CHARACTERISTIC kind read as ECU_ADDRESS_EXTENSION vs census VALUE (9 words on the /begin line) |
| 73 | embedconsult/quadesc | 1403 | CHARACTERISTIC kind read as ECU_ADDRESS_EXTENSION vs census VALUE (9 words on the /begin line) |
| 73 | embedconsult/quadesc | 1413 | CHARACTERISTIC kind read as ECU_ADDRESS_EXTENSION vs census VALUE (9 words on the /begin line) |
| 73 | embedconsult/quadesc | 1423 | CHARACTERISTIC kind read as ECU_ADDRESS_EXTENSION vs census VALUE (9 words on the /begin line) |
| 73 | embedconsult/quadesc | 1433 | CHARACTERISTIC kind read as ECU_ADDRESS_EXTENSION vs census VALUE (9 words on the /begin line) |
| 73 | embedconsult/quadesc | 0 | (+244 more of this class in this file; 252 in total) |
| 75 | disdi/XCPlite | 49 | CHARACTERISTIC kind read as None vs census VALUE (14 words on the /begin line) |
| 75 | disdi/XCPlite | 50 | CHARACTERISTIC kind read as None vs census VALUE (14 words on the /begin line) |
| 75 | disdi/XCPlite | 51 | CHARACTERISTIC kind read as None vs census VALUE (14 words on the /begin line) |
| 82 | songjmcn/libxcp | 97 | CHARACTERISTIC kind read as None vs census VAL_BLK (14 words on the /begin line) |
| 82 | songjmcn/libxcp | 98 | CHARACTERISTIC kind read as None vs census VAL_BLK (14 words on the /begin line) |
| 82 | songjmcn/libxcp | 99 | CHARACTERISTIC kind read as None vs census VAL_BLK (14 words on the /begin line) |
| 82 | songjmcn/libxcp | 100 | CHARACTERISTIC kind read as None vs census VAL_BLK (14 words on the /begin line) |
| 93 | PCTestAdmin/ECU-Studio-AI | 19 | CHARACTERISTIC kind read as None vs census MAP (9 words on the /begin line) |

(22 more rows in anomalies.json)

## DUPLICATE_NAME

| n | repo | line | structure |
|---|---|---|---|
| 18 | kallemooo/Asap2 | 150 | MEASUREMENT name occurs 4 times (first at line 133) |
| 20 | kallemooo/Asap2 | 183 | MEASUREMENT name occurs 4 times (first at line 166) |
| 21 | kallemooo/Asap2 | 150 | MEASUREMENT name occurs 4 times (first at line 133) |
| 26 | Vis6/elfreader-A2L-related | 14 | CHARACTERISTIC name occurs 3 times (first at line 1) |
| 26 | Vis6/elfreader-A2L-related | 53 | MEASUREMENT name occurs 3 times (first at line 40) |
| 28 | Vis6/elfreader-A2L-related | 229 | MEASUREMENT name occurs 138 times (first at line 7) |
| 28 | Vis6/elfreader-A2L-related | 295 | MEASUREMENT name occurs 211 times (first at line 55) |
| 28 | Vis6/elfreader-A2L-related | 4003 | MEASUREMENT name occurs 2 times (first at line 319) |
| 28 | Vis6/elfreader-A2L-related | 685 | MEASUREMENT name occurs 2 times (first at line 613) |
| 28 | Vis6/elfreader-A2L-related | 691 | MEASUREMENT name occurs 2 times (first at line 619) |
| 28 | Vis6/elfreader-A2L-related | 937 | MEASUREMENT name occurs 2 times (first at line 895) |
| 28 | Vis6/elfreader-A2L-related | 1477 | MEASUREMENT name occurs 2 times (first at line 1447) |
| 28 | Vis6/elfreader-A2L-related | 1675 | MEASUREMENT name occurs 2 times (first at line 1597) |
| 28 | Vis6/elfreader-A2L-related | 0 | (+2 more of this class in this file; 10 in total) |
| 48 | SKIFIN-IT-SERVICES/tapwright | 16 | MEASUREMENT name occurs 3 times (first at line 4) |
| 66 | sagarrthd/AI_Agent | 19 | CHARACTERISTIC name occurs 3 times (first at line 15) |
| 104 | jwhidte/VCU | 846 | MEASUREMENT name occurs 33 times (first at line 830) |
| 104 | jwhidte/VCU | 1375 | CHARACTERISTIC name occurs 75 times (first at line 1359) |
| 105 | jwhidte/VCU | 811 | MEASUREMENT name occurs 40 times (first at line 795) |
| 105 | jwhidte/VCU | 1450 | CHARACTERISTIC name occurs 52 times (first at line 1436) |
| 106 | jwhidte/VCU | 811 | MEASUREMENT name occurs 40 times (first at line 795) |
| 106 | jwhidte/VCU | 1450 | CHARACTERISTIC name occurs 58 times (first at line 1436) |
| 107 | jwhidte/VCU | 859 | MEASUREMENT name occurs 63 times (first at line 843) |
| 107 | jwhidte/VCU | 1868 | CHARACTERISTIC name occurs 136 times (first at line 1852) |
| 108 | maxar6/Wisconsin-Hybrid | 245 | MEASUREMENT name occurs 306 times (first at line 233) |
| 108 | maxar6/Wisconsin-Hybrid | 4061 | CHARACTERISTIC name occurs 216 times (first at line 4049) |
| 111 | keeper999/EngineControl_Aurix | 37 | MEASUREMENT name occurs 122 times (first at line 25) |
| 111 | keeper999/EngineControl_Aurix | 61 | CHARACTERISTIC name occurs 119 times (first at line 49) |
| 113 | keeper999/EngineControl_Aurix | 19 | CHARACTERISTIC name occurs 101 times (first at line 7) |
| 114 | keeper999/EngineControl_Aurix | 196 | CHARACTERISTIC name occurs 6 times (first at line 184) |
| 114 | keeper999/EngineControl_Aurix | 269 | MEASUREMENT name occurs 15 times (first at line 256) |
| 115 | Planetes1mal/NJUSZ-Intelligent-Software-and-Engineering | 627 | CHARACTERISTIC name occurs 70 times (first at line 592) |
| 115 | Planetes1mal/NJUSZ-Intelligent-Software-and-Engineering | 1538 | MEASUREMENT name occurs 271 times (first at line 1525) |
| 116 | EOSCogniton/ELIZ-2022 | 1560 | CHARACTERISTIC name occurs 10 times (first at line 1538) |
| 116 | EOSCogniton/ELIZ-2022 | 1786 | MEASUREMENT name occurs 59 times (first at line 1773) |
| 117 | EOSCogniton/ELIZ-2022 | 1560 | CHARACTERISTIC name occurs 10 times (first at line 1538) |
| 117 | EOSCogniton/ELIZ-2022 | 1786 | MEASUREMENT name occurs 59 times (first at line 1773) |
| 118 | EOSCogniton/ELIZ-2022 | 1560 | CHARACTERISTIC name occurs 10 times (first at line 1538) |
| 118 | EOSCogniton/ELIZ-2022 | 1786 | MEASUREMENT name occurs 59 times (first at line 1773) |
| 119 | EOSCogniton/ELIZ-2022 | 1560 | CHARACTERISTIC name occurs 10 times (first at line 1538) |

(29 more rows in anomalies.json)

## HDR_SHORT

| n | repo | line | structure |
|---|---|---|---|
| 2 | christoph2/pyA2L | 2 | MEASUREMENT header has 4 positional words, standard 8 |
| 61 | jasontaotao/a2l-editor | 4 | MEASUREMENT header has 0 positional words, standard 8 |
| 63 | code-2-git/vLenss | 10 | MEASUREMENT header has 1 positional words, standard 8 |
| 63 | code-2-git/vLenss | 17 | MEASUREMENT header has 1 positional words, standard 8 |
| 63 | code-2-git/vLenss | 24 | MEASUREMENT header has 1 positional words, standard 8 |
| 63 | code-2-git/vLenss | 31 | MEASUREMENT header has 1 positional words, standard 8 |
| 63 | code-2-git/vLenss | 38 | MEASUREMENT header has 1 positional words, standard 8 |
| 63 | code-2-git/vLenss | 45 | CHARACTERISTIC header has 1 positional words, standard 9 |
| 63 | code-2-git/vLenss | 52 | CHARACTERISTIC header has 1 positional words, standard 9 |
| 64 | ljh453/tester | 3 | MEASUREMENT header has 2 positional words, standard 8 |
| 64 | ljh453/tester | 6 | MEASUREMENT header has 2 positional words, standard 8 |
| 64 | ljh453/tester | 9 | CHARACTERISTIC header has 2 positional words, standard 9 |
| 65 | ljh453/tester | 3 | MEASUREMENT header has 2 positional words, standard 8 |
| 65 | ljh453/tester | 6 | MEASUREMENT header has 2 positional words, standard 8 |
| 65 | ljh453/tester | 9 | CHARACTERISTIC header has 2 positional words, standard 9 |
| 67 | usingarchbtw/fanatec-driving-simulator | 13 | CHARACTERISTIC header has 8 positional words, standard 9 |
| 67 | usingarchbtw/fanatec-driving-simulator | 30 | CHARACTERISTIC header has 8 positional words, standard 9 |
| 67 | usingarchbtw/fanatec-driving-simulator | 47 | CHARACTERISTIC header has 8 positional words, standard 9 |
| 67 | usingarchbtw/fanatec-driving-simulator | 64 | CHARACTERISTIC header has 8 positional words, standard 9 |

## KW_NOT_LINE_START

| n | repo | line | structure |
|---|---|---|---|
| 14 | vectorgrp/XCPlite | 47 | ECU_ADDRESS is not the first word on its line (current reader keys on the line-first word) |
| 14 | vectorgrp/XCPlite | 47 | ECU_ADDRESS_EXTENSION is not the first word on its line (current reader keys on the line-first word) |
| 14 | vectorgrp/XCPlite | 48 | ECU_ADDRESS is not the first word on its line (current reader keys on the line-first word) |
| 14 | vectorgrp/XCPlite | 48 | ECU_ADDRESS_EXTENSION is not the first word on its line (current reader keys on the line-first word) |
| 14 | vectorgrp/XCPlite | 49 | ECU_ADDRESS is not the first word on its line (current reader keys on the line-first word) |
| 14 | vectorgrp/XCPlite | 49 | ECU_ADDRESS_EXTENSION is not the first word on its line (current reader keys on the line-first word) |
| 14 | vectorgrp/XCPlite | 50 | ECU_ADDRESS is not the first word on its line (current reader keys on the line-first word) |
| 14 | vectorgrp/XCPlite | 50 | ECU_ADDRESS_EXTENSION is not the first word on its line (current reader keys on the line-first word) |
| 14 | vectorgrp/XCPlite | 0 | (+13 more of this class in this file; 21 in total) |
| 15 | vectorgrp/XCPlite | 72 | ECU_ADDRESS is not the first word on its line (current reader keys on the line-first word) |
| 15 | vectorgrp/XCPlite | 72 | ECU_ADDRESS_EXTENSION is not the first word on its line (current reader keys on the line-first word) |
| 15 | vectorgrp/XCPlite | 73 | ECU_ADDRESS is not the first word on its line (current reader keys on the line-first word) |
| 15 | vectorgrp/XCPlite | 73 | ECU_ADDRESS_EXTENSION is not the first word on its line (current reader keys on the line-first word) |
| 15 | vectorgrp/XCPlite | 74 | ECU_ADDRESS is not the first word on its line (current reader keys on the line-first word) |
| 15 | vectorgrp/XCPlite | 74 | ECU_ADDRESS_EXTENSION is not the first word on its line (current reader keys on the line-first word) |
| 16 | vectorgrp/XCPlite | 176 | MATRIX_DIM is not the first word on its line (current reader keys on the line-first word) |
| 16 | vectorgrp/XCPlite | 188 | ECU_ADDRESS is not the first word on its line (current reader keys on the line-first word) |
| 16 | vectorgrp/XCPlite | 188 | ECU_ADDRESS_EXTENSION is not the first word on its line (current reader keys on the line-first word) |
| 16 | vectorgrp/XCPlite | 189 | ECU_ADDRESS is not the first word on its line (current reader keys on the line-first word) |
| 16 | vectorgrp/XCPlite | 189 | ECU_ADDRESS_EXTENSION is not the first word on its line (current reader keys on the line-first word) |
| 16 | vectorgrp/XCPlite | 192 | ECU_ADDRESS is not the first word on its line (current reader keys on the line-first word) |
| 16 | vectorgrp/XCPlite | 192 | ECU_ADDRESS_EXTENSION is not the first word on its line (current reader keys on the line-first word) |
| 16 | vectorgrp/XCPlite | 193 | ECU_ADDRESS is not the first word on its line (current reader keys on the line-first word) |
| 16 | vectorgrp/XCPlite | 0 | (+33 more of this class in this file; 41 in total) |
| 17 | vectorgrp/XCPlite | 87 | MATRIX_DIM is not the first word on its line (current reader keys on the line-first word) |
| 17 | vectorgrp/XCPlite | 90 | ECU_ADDRESS is not the first word on its line (current reader keys on the line-first word) |
| 17 | vectorgrp/XCPlite | 90 | ECU_ADDRESS_EXTENSION is not the first word on its line (current reader keys on the line-first word) |
| 17 | vectorgrp/XCPlite | 91 | ECU_ADDRESS is not the first word on its line (current reader keys on the line-first word) |
| 17 | vectorgrp/XCPlite | 91 | ECU_ADDRESS_EXTENSION is not the first word on its line (current reader keys on the line-first word) |
| 17 | vectorgrp/XCPlite | 92 | ECU_ADDRESS is not the first word on its line (current reader keys on the line-first word) |
| 17 | vectorgrp/XCPlite | 92 | ECU_ADDRESS_EXTENSION is not the first word on its line (current reader keys on the line-first word) |
| 17 | vectorgrp/XCPlite | 93 | ECU_ADDRESS is not the first word on its line (current reader keys on the line-first word) |
| 17 | vectorgrp/XCPlite | 0 | (+13 more of this class in this file; 21 in total) |
| 44 | vectorgrp/xcp-lite | 149 | ECU_ADDRESS is not the first word on its line (current reader keys on the line-first word) |
| 44 | vectorgrp/xcp-lite | 149 | ECU_ADDRESS_EXTENSION is not the first word on its line (current reader keys on the line-first word) |
| 44 | vectorgrp/xcp-lite | 151 | ECU_ADDRESS is not the first word on its line (current reader keys on the line-first word) |
| 44 | vectorgrp/xcp-lite | 151 | ECU_ADDRESS_EXTENSION is not the first word on its line (current reader keys on the line-first word) |
| 45 | vectorgrp/xcp-lite | 148 | ECU_ADDRESS is not the first word on its line (current reader keys on the line-first word) |
| 45 | vectorgrp/xcp-lite | 148 | ECU_ADDRESS_EXTENSION is not the first word on its line (current reader keys on the line-first word) |
| 45 | vectorgrp/xcp-lite | 149 | ECU_ADDRESS is not the first word on its line (current reader keys on the line-first word) |

(76 more rows in anomalies.json)

## LEN_NONE_CHAR_RESOLVABLE_LAYOUT

| n | repo | line | structure |
|---|---|---|---|
| 4 | christoph2/pyA2L | 56 | CHARACTERISTIC VALUE with a record layout in the file but reader length None |
| 11 | DanielT/a2ltool | 78 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 13 | AKJ7/CANExplorer | 40 | CHARACTERISTIC VALUE with a record layout in the file but reader length None |
| 13 | AKJ7/CANExplorer | 42 | CHARACTERISTIC VALUE with a record layout in the file but reader length None |
| 13 | AKJ7/CANExplorer | 44 | CHARACTERISTIC VALUE with a record layout in the file but reader length None |
| 15 | vectorgrp/XCPlite | 69 | CHARACTERISTIC VALUE with a record layout in the file but reader length None |
| 15 | vectorgrp/XCPlite | 70 | CHARACTERISTIC VALUE with a record layout in the file but reader length None |
| 15 | vectorgrp/XCPlite | 71 | CHARACTERISTIC VALUE with a record layout in the file but reader length None |
| 19 | kallemooo/Asap2 | 3237 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 19 | kallemooo/Asap2 | 3251 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 19 | kallemooo/Asap2 | 3265 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 33 | mrom1/a2lparser | 3237 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 33 | mrom1/a2lparser | 3251 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 33 | mrom1/a2lparser | 3265 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 35 | mrom1/a2lparser | 3921 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 35 | mrom1/a2lparser | 3935 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 35 | mrom1/a2lparser | 3949 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 35 | mrom1/a2lparser | 4857 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 35 | mrom1/a2lparser | 4874 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 35 | mrom1/a2lparser | 4891 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 35 | mrom1/a2lparser | 4910 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 39 | domohuhn/a2l | 144 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 41 | asap2Go/calibrationReader | 4063 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 41 | asap2Go/calibrationReader | 4077 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 41 | asap2Go/calibrationReader | 4091 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 41 | asap2Go/calibrationReader | 5011 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 41 | asap2Go/calibrationReader | 5028 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 41 | asap2Go/calibrationReader | 5045 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 41 | asap2Go/calibrationReader | 5064 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 43 | asap2Go/calibrationReader | 4061 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 43 | asap2Go/calibrationReader | 4075 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 43 | asap2Go/calibrationReader | 4089 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 43 | asap2Go/calibrationReader | 5009 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 43 | asap2Go/calibrationReader | 5026 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 43 | asap2Go/calibrationReader | 5043 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 43 | asap2Go/calibrationReader | 5062 | CHARACTERISTIC VAL_BLK with a record layout in the file but reader length None |
| 44 | vectorgrp/xcp-lite | 159 | CHARACTERISTIC VALUE with a record layout in the file but reader length None |
| 44 | vectorgrp/xcp-lite | 160 | CHARACTERISTIC VALUE with a record layout in the file but reader length None |
| 44 | vectorgrp/xcp-lite | 162 | CHARACTERISTIC VALUE with a record layout in the file but reader length None |
| 44 | vectorgrp/xcp-lite | 163 | CHARACTERISTIC VALUE with a record layout in the file but reader length None |

(243 more rows in anomalies.json)

## LEN_NONE_MEAS_DATATYPE_DECLARED

| n | repo | line | structure |
|---|---|---|---|
| 2 | christoph2/pyA2L | 2 | MEASUREMENT datatype UWORD declared but reader length None |
| 4 | christoph2/pyA2L | 104 | MEASUREMENT datatype UWORD declared but reader length None |
| 4 | christoph2/pyA2L | 127 | MEASUREMENT datatype UWORD declared but reader length None |
| 4 | christoph2/pyA2L | 259 | MEASUREMENT datatype UWORD declared but reader length None |
| 5 | christoph2/pyxcp | 26 | MEASUREMENT datatype ULONG declared but reader length None |
| 14 | vectorgrp/XCPlite | 47 | MEASUREMENT datatype FLOAT64_IEEE declared but reader length None |
| 14 | vectorgrp/XCPlite | 48 | MEASUREMENT datatype FLOAT64_IEEE declared but reader length None |
| 14 | vectorgrp/XCPlite | 49 | MEASUREMENT datatype FLOAT64_IEEE declared but reader length None |
| 14 | vectorgrp/XCPlite | 50 | MEASUREMENT datatype FLOAT64_IEEE declared but reader length None |
| 14 | vectorgrp/XCPlite | 51 | MEASUREMENT datatype UBYTE declared but reader length None |
| 14 | vectorgrp/XCPlite | 52 | MEASUREMENT datatype FLOAT64_IEEE declared but reader length None |
| 14 | vectorgrp/XCPlite | 53 | MEASUREMENT datatype UWORD declared but reader length None |
| 14 | vectorgrp/XCPlite | 54 | MEASUREMENT datatype FLOAT64_IEEE declared but reader length None |
| 14 | vectorgrp/XCPlite | 0 | (+2 more of this class in this file; 10 in total) |
| 15 | vectorgrp/XCPlite | 72 | MEASUREMENT datatype ULONG declared but reader length None |
| 15 | vectorgrp/XCPlite | 73 | MEASUREMENT datatype FLOAT64_IEEE declared but reader length None |
| 15 | vectorgrp/XCPlite | 74 | MEASUREMENT datatype UWORD declared but reader length None |
| 16 | vectorgrp/XCPlite | 188 | MEASUREMENT datatype UWORD declared but reader length None |
| 16 | vectorgrp/XCPlite | 189 | MEASUREMENT datatype ULONG declared but reader length None |
| 16 | vectorgrp/XCPlite | 192 | MEASUREMENT datatype UWORD declared but reader length None |
| 16 | vectorgrp/XCPlite | 193 | MEASUREMENT datatype UWORD declared but reader length None |
| 16 | vectorgrp/XCPlite | 194 | MEASUREMENT datatype FLOAT32_IEEE declared but reader length None |
| 16 | vectorgrp/XCPlite | 195 | MEASUREMENT datatype ULONG declared but reader length None |
| 16 | vectorgrp/XCPlite | 196 | MEASUREMENT datatype ULONG declared but reader length None |
| 16 | vectorgrp/XCPlite | 197 | MEASUREMENT datatype ULONG declared but reader length None |
| 16 | vectorgrp/XCPlite | 0 | (+14 more of this class in this file; 22 in total) |
| 17 | vectorgrp/XCPlite | 90 | MEASUREMENT datatype FLOAT64_IEEE declared but reader length None |
| 17 | vectorgrp/XCPlite | 91 | MEASUREMENT datatype FLOAT64_IEEE declared but reader length None |
| 17 | vectorgrp/XCPlite | 92 | MEASUREMENT datatype A_UINT64 declared but reader length None |
| 17 | vectorgrp/XCPlite | 93 | MEASUREMENT datatype UBYTE declared but reader length None |
| 17 | vectorgrp/XCPlite | 94 | MEASUREMENT datatype FLOAT64_IEEE declared but reader length None |
| 17 | vectorgrp/XCPlite | 96 | MEASUREMENT datatype UWORD declared but reader length None |
| 17 | vectorgrp/XCPlite | 97 | MEASUREMENT datatype UWORD declared but reader length None |
| 17 | vectorgrp/XCPlite | 98 | MEASUREMENT datatype FLOAT64_IEEE declared but reader length None |
| 17 | vectorgrp/XCPlite | 0 | (+1 more of this class in this file; 9 in total) |
| 18 | kallemooo/Asap2 | 133 | MEASUREMENT datatype UWORD declared but reader length None |
| 18 | kallemooo/Asap2 | 150 | MEASUREMENT datatype UWORD declared but reader length None |
| 18 | kallemooo/Asap2 | 164 | MEASUREMENT datatype UWORD declared but reader length None |
| 18 | kallemooo/Asap2 | 178 | MEASUREMENT datatype UWORD declared but reader length None |
| 18 | kallemooo/Asap2 | 202 | MEASUREMENT datatype UBYTE declared but reader length None |

(374 more rows in anomalies.json)

## MEAS_DATATYPE_DIFFERENT

| n | repo | line | structure |
|---|---|---|---|
| 2 | christoph2/pyA2L | 2 | MEASUREMENT datatype read as None vs census UWORD (0 words on the /begin line) |
| 4 | christoph2/pyA2L | 104 | MEASUREMENT datatype read as 1 vs census UWORD (1 words on the /begin line) |
| 4 | christoph2/pyA2L | 127 | MEASUREMENT datatype read as 4 vs census UWORD (1 words on the /begin line) |
| 4 | christoph2/pyA2L | 259 | MEASUREMENT datatype read as R_SPEED_3 vs census UWORD (1 words on the /begin line) |
| 5 | christoph2/pyxcp | 26 | MEASUREMENT datatype read as None vs census ULONG (0 words on the /begin line) |
| 14 | vectorgrp/XCPlite | 47 | MEASUREMENT datatype read as None vs census FLOAT64_IEEE (13 words on the /begin line) |
| 14 | vectorgrp/XCPlite | 48 | MEASUREMENT datatype read as None vs census FLOAT64_IEEE (15 words on the /begin line) |
| 14 | vectorgrp/XCPlite | 49 | MEASUREMENT datatype read as None vs census FLOAT64_IEEE (13 words on the /begin line) |
| 14 | vectorgrp/XCPlite | 50 | MEASUREMENT datatype read as None vs census FLOAT64_IEEE (15 words on the /begin line) |
| 14 | vectorgrp/XCPlite | 51 | MEASUREMENT datatype read as None vs census UBYTE (13 words on the /begin line) |
| 14 | vectorgrp/XCPlite | 52 | MEASUREMENT datatype read as None vs census FLOAT64_IEEE (15 words on the /begin line) |
| 14 | vectorgrp/XCPlite | 53 | MEASUREMENT datatype read as None vs census UWORD (13 words on the /begin line) |
| 14 | vectorgrp/XCPlite | 54 | MEASUREMENT datatype read as None vs census FLOAT64_IEEE (13 words on the /begin line) |
| 14 | vectorgrp/XCPlite | 0 | (+2 more of this class in this file; 10 in total) |
| 15 | vectorgrp/XCPlite | 72 | MEASUREMENT datatype read as None vs census ULONG (13 words on the /begin line) |
| 15 | vectorgrp/XCPlite | 73 | MEASUREMENT datatype read as None vs census FLOAT64_IEEE (13 words on the /begin line) |
| 15 | vectorgrp/XCPlite | 74 | MEASUREMENT datatype read as None vs census UWORD (13 words on the /begin line) |
| 16 | vectorgrp/XCPlite | 188 | MEASUREMENT datatype read as None vs census UWORD (12 words on the /begin line) |
| 16 | vectorgrp/XCPlite | 189 | MEASUREMENT datatype read as /* vs census ULONG (12 words on the /begin line) |
| 16 | vectorgrp/XCPlite | 192 | MEASUREMENT datatype read as None vs census UWORD (12 words on the /begin line) |
| 16 | vectorgrp/XCPlite | 193 | MEASUREMENT datatype read as None vs census UWORD (11 words on the /begin line) |
| 16 | vectorgrp/XCPlite | 194 | MEASUREMENT datatype read as None vs census FLOAT32_IEEE (12 words on the /begin line) |
| 16 | vectorgrp/XCPlite | 195 | MEASUREMENT datatype read as None vs census ULONG (10 words on the /begin line) |
| 16 | vectorgrp/XCPlite | 196 | MEASUREMENT datatype read as None vs census ULONG (10 words on the /begin line) |
| 16 | vectorgrp/XCPlite | 197 | MEASUREMENT datatype read as None vs census ULONG (12 words on the /begin line) |
| 16 | vectorgrp/XCPlite | 0 | (+14 more of this class in this file; 22 in total) |
| 17 | vectorgrp/XCPlite | 90 | MEASUREMENT datatype read as None vs census FLOAT64_IEEE (15 words on the /begin line) |
| 17 | vectorgrp/XCPlite | 91 | MEASUREMENT datatype read as None vs census FLOAT64_IEEE (13 words on the /begin line) |
| 17 | vectorgrp/XCPlite | 92 | MEASUREMENT datatype read as None vs census A_UINT64 (13 words on the /begin line) |
| 17 | vectorgrp/XCPlite | 93 | MEASUREMENT datatype read as None vs census UBYTE (13 words on the /begin line) |
| 17 | vectorgrp/XCPlite | 94 | MEASUREMENT datatype read as None vs census FLOAT64_IEEE (13 words on the /begin line) |
| 17 | vectorgrp/XCPlite | 96 | MEASUREMENT datatype read as None vs census UWORD (13 words on the /begin line) |
| 17 | vectorgrp/XCPlite | 97 | MEASUREMENT datatype read as None vs census UWORD (13 words on the /begin line) |
| 17 | vectorgrp/XCPlite | 98 | MEASUREMENT datatype read as None vs census FLOAT64_IEEE (15 words on the /begin line) |
| 17 | vectorgrp/XCPlite | 0 | (+1 more of this class in this file; 9 in total) |
| 18 | kallemooo/Asap2 | 133 | MEASUREMENT datatype read as None vs census UWORD (0 words on the /begin line) |
| 18 | kallemooo/Asap2 | 150 | MEASUREMENT datatype read as None vs census UWORD (0 words on the /begin line) |
| 18 | kallemooo/Asap2 | 164 | MEASUREMENT datatype read as None vs census UWORD (0 words on the /begin line) |
| 18 | kallemooo/Asap2 | 178 | MEASUREMENT datatype read as None vs census UWORD (0 words on the /begin line) |
| 18 | kallemooo/Asap2 | 202 | MEASUREMENT datatype read as None vs census UBYTE (1 words on the /begin line) |

(379 more rows in anomalies.json)

## NAME_DIFFERENT

| n | repo | line | structure |
|---|---|---|---|
| 61 | jasontaotao/a2l-editor | 4 | MEASUREMENT reader name is different; census name token is on line 4 (0 words on the /begin line) |

## NAME_UNKNOWN_FROM_EMPTY_BEGIN_META

| n | repo | line | structure |
|---|---|---|---|
| 2 | christoph2/pyA2L | 2 | MEASUREMENT reader name is UNKNOWN; census name token is on line 2 (0 words on the /begin line) |
| 5 | christoph2/pyxcp | 26 | MEASUREMENT reader name is UNKNOWN; census name token is on line 26 (0 words on the /begin line) |
| 18 | kallemooo/Asap2 | 133 | MEASUREMENT reader name is UNKNOWN; census name token is on line 133 (0 words on the /begin line) |
| 18 | kallemooo/Asap2 | 150 | MEASUREMENT reader name is UNKNOWN; census name token is on line 150 (0 words on the /begin line) |
| 18 | kallemooo/Asap2 | 164 | MEASUREMENT reader name is UNKNOWN; census name token is on line 164 (0 words on the /begin line) |
| 18 | kallemooo/Asap2 | 178 | MEASUREMENT reader name is UNKNOWN; census name token is on line 178 (0 words on the /begin line) |
| 19 | kallemooo/Asap2 | 3294 | CHARACTERISTIC reader name is UNKNOWN; census name token is on line 3294 (0 words on the /begin line) |
| 20 | kallemooo/Asap2 | 166 | MEASUREMENT reader name is UNKNOWN; census name token is on line 166 (0 words on the /begin line) |
| 20 | kallemooo/Asap2 | 183 | MEASUREMENT reader name is UNKNOWN; census name token is on line 183 (0 words on the /begin line) |
| 20 | kallemooo/Asap2 | 197 | MEASUREMENT reader name is UNKNOWN; census name token is on line 197 (0 words on the /begin line) |
| 20 | kallemooo/Asap2 | 211 | MEASUREMENT reader name is UNKNOWN; census name token is on line 211 (0 words on the /begin line) |
| 21 | kallemooo/Asap2 | 133 | MEASUREMENT reader name is UNKNOWN; census name token is on line 133 (0 words on the /begin line) |
| 21 | kallemooo/Asap2 | 150 | MEASUREMENT reader name is UNKNOWN; census name token is on line 150 (0 words on the /begin line) |
| 21 | kallemooo/Asap2 | 164 | MEASUREMENT reader name is UNKNOWN; census name token is on line 164 (0 words on the /begin line) |
| 21 | kallemooo/Asap2 | 178 | MEASUREMENT reader name is UNKNOWN; census name token is on line 178 (0 words on the /begin line) |
| 26 | Vis6/elfreader-A2L-related | 1 | CHARACTERISTIC reader name is UNKNOWN; census name token is on line 1 (0 words on the /begin line) |
| 26 | Vis6/elfreader-A2L-related | 14 | CHARACTERISTIC reader name is UNKNOWN; census name token is on line 14 (0 words on the /begin line) |
| 26 | Vis6/elfreader-A2L-related | 27 | CHARACTERISTIC reader name is UNKNOWN; census name token is on line 27 (0 words on the /begin line) |
| 26 | Vis6/elfreader-A2L-related | 40 | MEASUREMENT reader name is UNKNOWN; census name token is on line 40 (0 words on the /begin line) |
| 26 | Vis6/elfreader-A2L-related | 53 | MEASUREMENT reader name is UNKNOWN; census name token is on line 53 (0 words on the /begin line) |
| 26 | Vis6/elfreader-A2L-related | 66 | MEASUREMENT reader name is UNKNOWN; census name token is on line 66 (0 words on the /begin line) |
| 33 | mrom1/a2lparser | 3294 | CHARACTERISTIC reader name is UNKNOWN; census name token is on line 3294 (0 words on the /begin line) |
| 34 | mrom1/a2lparser | 78 | CHARACTERISTIC reader name is UNKNOWN; census name token is on line 78 (0 words on the /begin line) |
| 35 | mrom1/a2lparser | 3978 | CHARACTERISTIC reader name is UNKNOWN; census name token is on line 3978 (0 words on the /begin line) |
| 41 | asap2Go/calibrationReader | 4120 | CHARACTERISTIC reader name is UNKNOWN; census name token is on line 4120 (0 words on the /begin line) |
| 43 | asap2Go/calibrationReader | 4118 | CHARACTERISTIC reader name is UNKNOWN; census name token is on line 4118 (0 words on the /begin line) |
| 48 | SKIFIN-IT-SERVICES/tapwright | 4 | MEASUREMENT reader name is UNKNOWN; census name token is on line 4 (0 words on the /begin line) |
| 48 | SKIFIN-IT-SERVICES/tapwright | 16 | MEASUREMENT reader name is UNKNOWN; census name token is on line 16 (0 words on the /begin line) |
| 48 | SKIFIN-IT-SERVICES/tapwright | 28 | MEASUREMENT reader name is UNKNOWN; census name token is on line 28 (0 words on the /begin line) |
| 57 | goldr0g3r/tethys | 3 | CHARACTERISTIC reader name is UNKNOWN; census name token is on line 3 (0 words on the /begin line) |
| 59 | goldr0g3r/tethys | 3 | MEASUREMENT reader name is UNKNOWN; census name token is on line 3 (0 words on the /begin line) |
| 66 | sagarrthd/AI_Agent | 15 | CHARACTERISTIC reader name is UNKNOWN; census name token is on line 15 (0 words on the /begin line) |
| 66 | sagarrthd/AI_Agent | 19 | CHARACTERISTIC reader name is UNKNOWN; census name token is on line 19 (0 words on the /begin line) |
| 66 | sagarrthd/AI_Agent | 23 | CHARACTERISTIC reader name is UNKNOWN; census name token is on line 23 (0 words on the /begin line) |
| 77 | caesarhao/AutoSolution | 3294 | CHARACTERISTIC reader name is UNKNOWN; census name token is on line 3294 (0 words on the /begin line) |
| 79 | caesarhao/AutoSolution | 3978 | CHARACTERISTIC reader name is UNKNOWN; census name token is on line 3978 (0 words on the /begin line) |
| 92 | muellerj/a2l-parser | 3294 | CHARACTERISTIC reader name is UNKNOWN; census name token is on line 3294 (0 words on the /begin line) |
| 104 | jwhidte/VCU | 830 | MEASUREMENT reader name is UNKNOWN; census name token is on line 830 (0 words on the /begin line) |
| 104 | jwhidte/VCU | 846 | MEASUREMENT reader name is UNKNOWN; census name token is on line 846 (0 words on the /begin line) |
| 104 | jwhidte/VCU | 862 | MEASUREMENT reader name is UNKNOWN; census name token is on line 862 (0 words on the /begin line) |

(240 more rows in anomalies.json)
