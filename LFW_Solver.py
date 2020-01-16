_LIMIT_SEARCH_COUNT = 100

_AREADY_VISITED = []

# _ORDERED_WALK_DICT[given node] = [adjacency nodes which are connected with normal walk road from given node (higher than given node's number only)]
_ORDERED_WALK_DICT = {}
_ORDERED_WALK_DICT[1] = [2, 9, 8, 28, 26, 7, 6, 24]
_ORDERED_WALK_DICT[2] = [3, 11, 9, 8, 28, 26]
_ORDERED_WALK_DICT[3] = [5, 4, 11, 9]
_ORDERED_WALK_DICT[4] = [5, 12, 30, 10, 11]
_ORDERED_WALK_DICT[5] = [17, 16, 15, 13, 12]
_ORDERED_WALK_DICT[6] = [7, 26, 44, 25, 24]
_ORDERED_WALK_DICT[7] = [26, 44, 25, 24]
_ORDERED_WALK_DICT[8] = [9, 10, 28, 26]
_ORDERED_WALK_DICT[9] = [11, 10, 28, 26]
_ORDERED_WALK_DICT[10] = [11, 12, 30]
_ORDERED_WALK_DICT[11] = [12, 30]
_ORDERED_WALK_DICT[12] = [17, 16, 15, 13, 30]
_ORDERED_WALK_DICT[13] = [17, 16, 15, 14, 32, 30]
_ORDERED_WALK_DICT[14] = [33, 54, 52, 31, 32, 30]
_ORDERED_WALK_DICT[15] = [17, 16, 36, 35, 34, 33]
_ORDERED_WALK_DICT[16] = [17, 36, 35, 34, 33]
_ORDERED_WALK_DICT[17] = [18, 38, 36]
_ORDERED_WALK_DICT[18] = [20, 19, 39, 38, 36]
_ORDERED_WALK_DICT[19] = [20, 39]
_ORDERED_WALK_DICT[20] = [21, 42, 41, 40]
_ORDERED_WALK_DICT[21] = [23, 42, 41, 40]
_ORDERED_WALK_DICT[22] = [23, 77, 42]
_ORDERED_WALK_DICT[23] = [77]
_ORDERED_WALK_DICT[24] = [26, 44, 25, 59, 43]
_ORDERED_WALK_DICT[25] = [26, 44, 59, 43]
_ORDERED_WALK_DICT[26] = [28, 27, 46, 79, 44]
_ORDERED_WALK_DICT[27] = [28, 29, 48, 47, 45, 46, 44]
_ORDERED_WALK_DICT[28] = [29, 48, 47, 46]
_ORDERED_WALK_DICT[29] = [30, 50, 66, 64, 49, 48, 47, 45, 46]
_ORDERED_WALK_DICT[30] = [32, 50, 66, 64, 49]
_ORDERED_WALK_DICT[31] = [32, 33, 54, 52, 51, 50]
_ORDERED_WALK_DICT[32] = [33, 54, 52, 31]
_ORDERED_WALK_DICT[33] = [36, 35, 34, 54, 52]
_ORDERED_WALK_DICT[34] = [36, 35, 37, 55, 68, 53, 54]
_ORDERED_WALK_DICT[35] = [36, 37, 55, 68, 53, 54]
_ORDERED_WALK_DICT[36] = [38]
_ORDERED_WALK_DICT[37] = [38, 39, 55, 68, 53, 54]
_ORDERED_WALK_DICT[38] = [39]
_ORDERED_WALK_DICT[39] = [56]
_ORDERED_WALK_DICT[40] = [42, 41, 58, 73, 57]
_ORDERED_WALK_DICT[41] = [42, 58, 73, 57]
_ORDERED_WALK_DICT[42] = [58, 73, 57]
_ORDERED_WALK_DICT[43] = [44, 59]
_ORDERED_WALK_DICT[44] = [46, 79, 59]
_ORDERED_WALK_DICT[45] = [48, 47, 61]
_ORDERED_WALK_DICT[46] = [48, 47]
_ORDERED_WALK_DICT[47] = [48, 61]
_ORDERED_WALK_DICT[48] = [49, 64, 63, 62]
_ORDERED_WALK_DICT[49] = [50, 66, 64, 63, 62]
_ORDERED_WALK_DICT[50] = [52, 51, 66, 64]
_ORDERED_WALK_DICT[51] = [52, 67, 84, 65, 66]
_ORDERED_WALK_DICT[52] = [54, 53, 67]
_ORDERED_WALK_DICT[53] = [54, 55, 68, 67]
_ORDERED_WALK_DICT[54] = [55, 68]
_ORDERED_WALK_DICT[55] = [56, 69, 102, 86, 68]
_ORDERED_WALK_DICT[56] = [57, 69, 102, 86, 68]
_ORDERED_WALK_DICT[57] = [58, 73]
_ORDERED_WALK_DICT[58] = [76, 75, 74, 73]
_ORDERED_WALK_DICT[59] = [60, 78, 96, 95]
_ORDERED_WALK_DICT[60] = [79, 78, 96, 95]
_ORDERED_WALK_DICT[61] = []
_ORDERED_WALK_DICT[62] = [64, 63, 82, 98, 80]
_ORDERED_WALK_DICT[63] = [64, 65, 83, 82]
_ORDERED_WALK_DICT[64] = [66]
_ORDERED_WALK_DICT[65] = [66, 67, 84, 83, 82]
_ORDERED_WALK_DICT[66] = [67, 84, 65]
_ORDERED_WALK_DICT[67] = [84]
_ORDERED_WALK_DICT[68] = [69, 102, 86]
_ORDERED_WALK_DICT[69] = [70, 103, 127, 102, 86]
_ORDERED_WALK_DICT[70] = [71, 87, 103]
_ORDERED_WALK_DICT[71] = [72, 88, 104, 87]
_ORDERED_WALK_DICT[72] = [73, 74, 90, 89, 88]
_ORDERED_WALK_DICT[73] = [76, 75, 74, 90, 89]
_ORDERED_WALK_DICT[74] = [76, 75, 90, 89]
_ORDERED_WALK_DICT[75] = [76, 77, 94, 93, 92, 91, 90]
_ORDERED_WALK_DICT[76] = [77, 94, 93, 92, 91, 90]
_ORDERED_WALK_DICT[77] = [94, 93, 92, 91, 90]
_ORDERED_WALK_DICT[78] = [79, 80, 97, 96, 95]
_ORDERED_WALK_DICT[79] = [80, 97]
_ORDERED_WALK_DICT[80] = [82, 98, 81, 97]
_ORDERED_WALK_DICT[81] = [138]
_ORDERED_WALK_DICT[82] = [83, 98]
_ORDERED_WALK_DICT[83] = [99, 100, 120]
_ORDERED_WALK_DICT[84] = [86, 85, 100, 99]
_ORDERED_WALK_DICT[85] = [86, 101, 126, 124, 100, 99]
_ORDERED_WALK_DICT[86] = [102, 100, 99]
_ORDERED_WALK_DICT[87] = [104, 129]
_ORDERED_WALK_DICT[88] = [105, 130, 104]
_ORDERED_WALK_DICT[89] = [90, 91, 107, 106, 105]
_ORDERED_WALK_DICT[90] = [94, 93, 92, 91]
_ORDERED_WALK_DICT[91] = [94, 93, 92, 107, 106, 105]
_ORDERED_WALK_DICT[92] = [94, 93, 109, 110, 132, 108, 107]
_ORDERED_WALK_DICT[93] = [94, 111, 110, 109]
_ORDERED_WALK_DICT[94] = [111, 110, 109]
_ORDERED_WALK_DICT[95] = [96, 114, 113, 112]
_ORDERED_WALK_DICT[96] = [97, 116, 115, 114, 113, 112]
_ORDERED_WALK_DICT[97] = [117, 116, 115]
_ORDERED_WALK_DICT[98] = [120, 122, 123, 121, 119, 118]
_ORDERED_WALK_DICT[99] = [100, 120]
_ORDERED_WALK_DICT[100] = [124, 125, 155, 141, 170, 140, 123, 122, 120]
_ORDERED_WALK_DICT[101] = [102, 127, 143, 142, 156, 125, 126, 124]
_ORDERED_WALK_DICT[102] = [127, 143, 142, 156, 125, 126]
_ORDERED_WALK_DICT[103] = [128, 127]
_ORDERED_WALK_DICT[104] = [105, 130, 145, 129]
_ORDERED_WALK_DICT[105] = [107, 106, 130]
_ORDERED_WALK_DICT[106] = [107, 108, 132, 134, 133, 131]
_ORDERED_WALK_DICT[107] = [109, 110, 132, 108]
_ORDERED_WALK_DICT[108] = [109, 110, 132, 134, 133, 131]
_ORDERED_WALK_DICT[109] = [111, 110, 132]
_ORDERED_WALK_DICT[110] = [111, 132]
_ORDERED_WALK_DICT[111] = [147, 134]
_ORDERED_WALK_DICT[112] = [114, 113, 135, 148, 162]
_ORDERED_WALK_DICT[113] = [114, 137, 138, 136, 148, 135]
_ORDERED_WALK_DICT[114] = [115, 137, 138, 136, 148, 135]
_ORDERED_WALK_DICT[115] = [116, 137]
_ORDERED_WALK_DICT[116] = [117, 118, 151, 150, 139]
_ORDERED_WALK_DICT[117] = [118, 151, 150, 139]
_ORDERED_WALK_DICT[118] = [120, 122, 123, 121, 119, 151, 150, 139]
_ORDERED_WALK_DICT[119] = [120, 122, 123, 121, 153, 151]
_ORDERED_WALK_DICT[120] = [122, 123, 121]
_ORDERED_WALK_DICT[121] = [122, 123, 153, 151]
_ORDERED_WALK_DICT[122] = [124, 125, 155, 141, 170, 140, 123]
_ORDERED_WALK_DICT[123] = [124, 125, 155, 141, 170, 140]
_ORDERED_WALK_DICT[124] = [126, 125, 155, 141, 170, 140]
_ORDERED_WALK_DICT[125] = [126, 127, 143, 142, 156, 155, 141, 170, 140]
_ORDERED_WALK_DICT[126] = [127, 143, 142, 156]
_ORDERED_WALK_DICT[127] = [128, 143, 142, 156]
_ORDERED_WALK_DICT[128] = [144, 159, 143]
_ORDERED_WALK_DICT[129] = [145, 150, 173, 159, 144]
_ORDERED_WALK_DICT[130] = [131, 146, 161, 145]
_ORDERED_WALK_DICT[131] = [132, 134, 133, 146, 161, 145]
_ORDERED_WALK_DICT[132] = [134, 133]
_ORDERED_WALK_DICT[133] = [134, 147, 146]
_ORDERED_WALK_DICT[134] = [147]
_ORDERED_WALK_DICT[135] = [137, 138, 136, 148, 162]
_ORDERED_WALK_DICT[136] = [137, 138, 139, 164, 174, 163, 149, 148]
_ORDERED_WALK_DICT[137] = [138, 148]
_ORDERED_WALK_DICT[138] = [139, 164, 174, 163, 149, 148]
_ORDERED_WALK_DICT[139] = [151, 150, 164, 174, 163, 149]
_ORDERED_WALK_DICT[140] = [155, 141, 170, 154, 180, 152, 153]
_ORDERED_WALK_DICT[141] = [155, 170]
_ORDERED_WALK_DICT[142] = [143, 158, 156]
_ORDERED_WALK_DICT[143] = [144, 159, 158, 156]
_ORDERED_WALK_DICT[144] = [145, 160, 173, 159]
_ORDERED_WALK_DICT[145] = [146, 161, 150, 173, 159]
_ORDERED_WALK_DICT[146] = [147, 161]
_ORDERED_WALK_DICT[147] = []
_ORDERED_WALK_DICT[148] = [149, 163, 162]
_ORDERED_WALK_DICT[149] = [164, 174, 163, 162]
_ORDERED_WALK_DICT[150] = [151, 166, 176]
_ORDERED_WALK_DICT[151] = [153, 166, 176]
_ORDERED_WALK_DICT[152] = [153, 154, 168, 180, 167, 178, 177, 165, 166]
_ORDERED_WALK_DICT[153] = [154, 168, 180]
_ORDERED_WALK_DICT[154] = [170, 169, 168, 180]
_ORDERED_WALK_DICT[155] = [182, 181, 170]
_ORDERED_WALK_DICT[156] = [157, 171, 183]
_ORDERED_WALK_DICT[157] = [158, 159, 172, 185, 171, 183]
_ORDERED_WALK_DICT[158] = [159, 172, 185, 171]
_ORDERED_WALK_DICT[159] = [160, 173, 195, 187, 185, 172, 171]
_ORDERED_WALK_DICT[160] = [161, 173]
_ORDERED_WALK_DICT[161] = []
_ORDERED_WALK_DICT[162] = [163]
_ORDERED_WALK_DICT[163] = [164, 174]
_ORDERED_WALK_DICT[164] = [175, 188, 174]
_ORDERED_WALK_DICT[165] = [167, 178, 177, 189, 166]
_ORDERED_WALK_DICT[166] = [167, 178, 177, 176]
_ORDERED_WALK_DICT[167] = [179, 178, 177]
_ORDERED_WALK_DICT[168] = [170, 169, 180]
_ORDERED_WALK_DICT[169] = [170, 181, 191, 180]
_ORDERED_WALK_DICT[170] = [182, 181]
_ORDERED_WALK_DICT[171] = [172, 185, 183]
_ORDERED_WALK_DICT[172] = [173, 195, 187, 185]
_ORDERED_WALK_DICT[173] = [195, 187, 185]
_ORDERED_WALK_DICT[174] = [175, 188]
_ORDERED_WALK_DICT[175] = [176, 190, 188]
_ORDERED_WALK_DICT[176] = [190, 188]
_ORDERED_WALK_DICT[177] = [178, 180]
_ORDERED_WALK_DICT[178] = [179, 191, 190, 189]
_ORDERED_WALK_DICT[179] = [191, 190, 189]
_ORDERED_WALK_DICT[180] = [181, 191]
_ORDERED_WALK_DICT[181] = [182, 191]
_ORDERED_WALK_DICT[182] = [183, 185, 186, 193, 184, 192]
_ORDERED_WALK_DICT[183] = [185, 186, 193, 184, 192]
_ORDERED_WALK_DICT[184] = [185, 186, 193, 192]
_ORDERED_WALK_DICT[185] = [187, 186, 193, 192]
_ORDERED_WALK_DICT[186] = [187, 195, 194, 193, 192]
_ORDERED_WALK_DICT[187] = [195, 194, 193]
_ORDERED_WALK_DICT[188] = [190]
_ORDERED_WALK_DICT[189] = [190, 191]
_ORDERED_WALK_DICT[190] = [191]
_ORDERED_WALK_DICT[191] = []
_ORDERED_WALK_DICT[192] = [193, 194]
_ORDERED_WALK_DICT[193] = [194, 195]
_ORDERED_WALK_DICT[194] = [195]
_ORDERED_WALK_DICT[195] = []

# _ORDERED_WALK_DICT -> _WALK_DICT automatic creation
# _WALK_DICT[given node] = [adjacency nodes which are connected with normal walk road from given node]
_WALK_DICT = {}
def initWalkDict(exceptTrace = []):    
    for start, endList in _ORDERED_WALK_DICT.items():
        for end in endList:
            if _WALK_DICT.has_key(start) == False:
                _WALK_DICT[start] = []
            if end not in _WALK_DICT[start] and end not in exceptTrace:
                _WALK_DICT[start].append(end)
            
            if _WALK_DICT.has_key(end) == False:
                _WALK_DICT[end] = []
            if start not in _WALK_DICT[end] and start not in exceptTrace:
                _WALK_DICT[end].append(start)

    #print '_WALK_DICT'
    #print _WALK_DICT

# _ALLEY_LIST[...] = [[adjacency nodes which are connected with ALLEY], ...]
_ALLEY_LIST = []
# west side
_ALLEY_LIST.append([6, 24])
_ALLEY_LIST.append([6, 7])
_ALLEY_LIST.append([1, 7, 26])
_ALLEY_LIST.append([26])
_ALLEY_LIST.append([24, 25])
_ALLEY_LIST.append([25, 44])
_ALLEY_LIST.append([26, 44])
_ALLEY_LIST.append([26, 27, 28])
_ALLEY_LIST.append([27, 46])
_ALLEY_LIST.append([43])
_ALLEY_LIST.append([44, 59, 60, 79])
_ALLEY_LIST.append([60, 78])
_ALLEY_LIST.append([78, 79])
_ALLEY_LIST.append([46, 45, 47, 48, 61, 79, 80, 62])
_ALLEY_LIST.append([45, 47])
_ALLEY_LIST.append([47])
_ALLEY_LIST.append([61])
_ALLEY_LIST.append([135, 148])
_ALLEY_LIST.append([112, 113, 135])
_ALLEY_LIST.append([113, 114])
_ALLEY_LIST.append([95, 96])
_ALLEY_LIST.append([148, 152])
_ALLEY_LIST.append([136, 148, 149])
_ALLEY_LIST.append([149, 163])
_ALLEY_LIST.append([136, 138])
_ALLEY_LIST.append([114, 137])
_ALLEY_LIST.append([96, 114, 115])
_ALLEY_LIST.append([115, 116, 137, 138, 139])
_ALLEY_LIST.append([78, 96, 97])
_ALLEY_LIST.append([97, 116, 117])
_ALLEY_LIST.append([80, 81, 97, 117, 118])
_ALLEY_LIST.append([80, 81, 98, 118])
# north side
_ALLEY_LIST.append([2, 9])
_ALLEY_LIST.append([9, 8])
_ALLEY_LIST.append([3, 4, 11])
_ALLEY_LIST.append([11, 9, 10])
_ALLEY_LIST.append([8, 10, 28, 30, 29])
_ALLEY_LIST.append([29, 48, 49])
_ALLEY_LIST.append([48])
_ALLEY_LIST.append([49, 64])
_ALLEY_LIST.append([62, 63, 82])
_ALLEY_LIST.append([64, 63, 66, 65])
_ALLEY_LIST.append([82, 98, 83, 120])
_ALLEY_LIST.append([65, 83, 84, 99])
_ALLEY_LIST.append([5, 4, 12])
_ALLEY_LIST.append([12, 13, 30])
_ALLEY_LIST.append([30, 32, 50, 31])
_ALLEY_LIST.append([50, 51, 66])
_ALLEY_LIST.append([31, 52])
_ALLEY_LIST.append([51, 52, 67])
_ALLEY_LIST.append([14, 32])
_ALLEY_LIST.append([54])
_ALLEY_LIST.append([52, 54, 53])
_ALLEY_LIST.append([13, 14, 15, 33])
_ALLEY_LIST.append([33, 54, 34])
_ALLEY_LIST.append([15, 16])
_ALLEY_LIST.append([34, 35])
_ALLEY_LIST.append([17, 16, 36])
_ALLEY_LIST.append([36, 35, 38, 37])
_ALLEY_LIST.append([18, 38, 39])
_ALLEY_LIST.append([18, 19])
_ALLEY_LIST.append([53, 67, 68, 84])
_ALLEY_LIST.append([55, 68])
_ALLEY_LIST.append([39, 37, 55, 56])
_ALLEY_LIST.append([19, 20, 39, 40, 56, 57])
_ALLEY_LIST.append([40, 41, 41, 42])    # insert 42
_ALLEY_LIST.append([21, 23, 22, 42])    # insert 22, 42
# south-west side
_ALLEY_LIST.append([164, 174])
_ALLEY_LIST.append([139, 150, 164, 176, 175])
_ALLEY_LIST.append([175, 188])
_ALLEY_LIST.append([118, 119])
_ALLEY_LIST.append([150, 151])
_ALLEY_LIST.append([153, 151, 152, 166])
_ALLEY_LIST.append([166, 165, 176, 189, 190])
_ALLEY_LIST.append([165, 177])
_ALLEY_LIST.append([177, 178])
_ALLEY_LIST.append([178, 189])
_ALLEY_LIST.append([152, 167, 180, 179, 191])
_ALLEY_LIST.append([167, 178])
_ALLEY_LIST.append([178, 179])
# south-east side
_ALLEY_LIST.append([119, 121])
_ALLEY_LIST.append([121])
_ALLEY_LIST.append([123, 121, 140, 153])
_ALLEY_LIST.append([154, 168])
_ALLEY_LIST.append([168, 169, 180])
_ALLEY_LIST.append([140, 154, 170])
_ALLEY_LIST.append([170, 169, 181])
_ALLEY_LIST.append([141])
_ALLEY_LIST.append([141, 155, 170])
_ALLEY_LIST.append([125, 155, 156, 183, 182])
_ALLEY_LIST.append([143, 142])
_ALLEY_LIST.append([142, 156, 158, 157])
_ALLEY_LIST.append([157, 171])
_ALLEY_LIST.append([171, 183])
_ALLEY_LIST.append([183, 185])
_ALLEY_LIST.append([184, 192])
_ALLEY_LIST.append([184, 193])
_ALLEY_LIST.append([158, 159, 143]) # except 143
_ALLEY_LIST.append([172, 185])
_ALLEY_LIST.append([185, 187, 186])
_ALLEY_LIST.append([186, 193])
_ALLEY_LIST.append([193, 194])
_ALLEY_LIST.append([144, 159])
_ALLEY_LIST.append([159, 172])
_ALLEY_LIST.append([144, 159])
_ALLEY_LIST.append([159, 173])
_ALLEY_LIST.append([187, 195])
_ALLEY_LIST.append([145, 160])
_ALLEY_LIST.append([145, 161, 160])
_ALLEY_LIST.append([161])
# east side
_ALLEY_LIST.append([99, 100])
_ALLEY_LIST.append([100, 122, 120]) # except 120
_ALLEY_LIST.append([122, 123])
_ALLEY_LIST.append([85, 100, 124])
_ALLEY_LIST.append([124, 126, 125])
_ALLEY_LIST.append([86, 85, 101, 102])
_ALLEY_LIST.append([101, 126])
_ALLEY_LIST.append([126])
_ALLEY_LIST.append([56, 57, 73, 69, 70, 71, 72])
_ALLEY_LIST.append([69, 102, 127])
_ALLEY_LIST.append([69, 103, 127])
_ALLEY_LIST.append([127, 128, 143])
_ALLEY_LIST.append([70, 87, 103, 129, 128, 144])
_ALLEY_LIST.append([71, 87, 104])
_ALLEY_LIST.append([71, 88, 104])
_ALLEY_LIST.append([104, 129, 145])  # except 145
_ALLEY_LIST.append([104, 130, 145])
_ALLEY_LIST.append([72, 88, 89, 105])
_ALLEY_LIST.append([105, 106, 130, 131])
_ALLEY_LIST.append([58])
_ALLEY_LIST.append([58, 73])
_ALLEY_LIST.append([73, 74])
_ALLEY_LIST.append([74, 75, 90])
_ALLEY_LIST.append([90, 89, 91])
_ALLEY_LIST.append([91, 92, 107])
_ALLEY_LIST.append([107, 106, 108])
_ALLEY_LIST.append([108, 132])
_ALLEY_LIST.append([131, 133, 146])
_ALLEY_LIST.append([22, 42, 58, 76, 77]) # insert 22, 42
_ALLEY_LIST.append([76, 75])
_ALLEY_LIST.append([94, 93])
_ALLEY_LIST.append([93, 92])
_ALLEY_LIST.append([109, 110])
_ALLEY_LIST.append([110, 132, 111, 134])
_ALLEY_LIST.append([134, 133, 147])

# _ALLEY_LIST -> _ALLEY_DICT automatic creation
# _ALLEY_DICT[given node] = [adjacency nodes which are connected with alley road]
_ALLEY_DICT = {}
def initAlleyDict(exceptTrace = []):    
    for alley in _ALLEY_LIST:
        for startIndex in range(len(alley)):
            start = alley[startIndex]
            for endIndex in range(startIndex + 1, len(alley)):
                end = alley[endIndex]
                
                if _ALLEY_DICT.has_key(start) == False:
                    _ALLEY_DICT[start] = []
                if end not in _ALLEY_DICT[start] and end not in exceptTrace:
                    _ALLEY_DICT[start].append(end)
                
                if _ALLEY_DICT.has_key(end) == False:
                    _ALLEY_DICT[end] = []
                if start not in _ALLEY_DICT[end] and start not in exceptTrace:
                    _ALLEY_DICT[end].append(start)

    #print '_ALLEY_DICT'
    #print _ALLEY_DICT

def doWalk(presentNode):
    try:
        nextNodeList = _WALK_DICT[presentNode]
    except:
        nextNodeList = []
        
    return nextNodeList
   
def doCoach(presentNode):
    tempNodeList = doWalk(presentNode)
    nextNodeList = []
    for tempNode in tempNodeList:
        #print tempNode, _WALK_DICT[tempNode]
        nextNodeList.extend(doWalk(tempNode))
        
    return list(set(nextNodeList))
       
def doAlley(presentNode):
    try:
        nextNodeList = _ALLEY_DICT[presentNode]
    except:
        nextNodeList = []
        
    return nextNodeList
    
# get all nodes which can reached from given node by given 1 movement action (walk, coach, alley)
def getNextNodeList(presentNode, presentMove):
    nextNodeList = []
    
    try:
        # by walk
        if presentMove == 'w':
            nextNodeList = doWalk(presentNode)
        # by coach (walk 2 times)
        elif presentMove == 'c':
            nextNodeList = doCoach(presentNode)
        # by alley
        elif presentMove == 'a':
            nextNodeList = doAlley(presentNode)
        elif presentMove == None:
            pass
        else:
            print 'ERROR: Unknown Move', presentMove
    except:
        print 'WARNING: Unknown Way', presentNode, presentMove, nextNodeList
    
    filteredList = []
    for node in nextNodeList:
        if node not in _AREADY_VISITED:
            filteredList.append(node)
    
    return filteredList
            
# get all nodes which can reached from given node by given movement action sequence (walk, coach, alley)
def getCandidateList(startNode, moveSequence):
    #print 'startNode', startNode
    #print 'moveSequence', moveSequence

    presentNode = startNode
    moveCount = 0
    presentMove = moveSequence[moveCount]
    
    # put starting node into search queue
    moveQueue = []
    moveQueue.append([moveCount, presentNode, presentMove])
    searchCount = 0
    
    candidateList = []
    while len(moveQueue) > 0:
        #print '===== ===== ====='
        #print 'moveQueue', moveQueue
        
        # pop 1 item from search queue
        moveCount, presentNode, presentMove = moveQueue.pop(0)
        
        _AREADY_VISITED.append(presentNode)
        
        #print moveCount, presentNode, presentMove
        #print '===== ===== ====='
        
        # get all nodes which can reached from present node by given 1 movement action
        nextNodeList = getNextNodeList(presentNode, presentMove)
        
        #if len(nextNodeList) == 0:
        #    continue
        
        # expanding search area if movement action is available
        if moveCount < len(moveSequence) - 1:
            nextMove = moveSequence[moveCount + 1]
        else:
            nextMove = None
            
        for nextNode in nextNodeList:
            # adding candidate node
            if nextNode not in candidateList:
                candidateList.append(nextNode)
                
            # adding next search node
            moveQueue.append([moveCount + 1, nextNode, nextMove])
            #print '>>>', moveCount + 1, nextNode, nextMove
        
        print moveCount,
        
        searchCount += 1
        
        if searchCount > _LIMIT_SEARCH_COUNT:
            print
            print 'WARNING: limit search count!', _LIMIT_SEARCH_COUNT
            break

    print
        
    return candidateList
            
if __name__ == '__main__':
    # [Usage]
    # 1. Find the optimal movement count from victim node to the farthest clue node
    # 2. Input farthest clue node to 'startNode'
    # 3. Input the left movement sequence from farthest clue node to 'moveSequence'
    # 4. (Optional) Input innocent node list to 'exceptTrace'
    # 5. Run
    # 6. Output means candidate node list
    # [Param] startNode = farthest clue node
    # [Param] moveSequence = left movement sequence from farthest clue node (w = walk, c = coach, a = alley)
    # [Param] exceptTrace = innocent node list
    
    startNode = int(raw_input("input startNode: "))
    moveSequence = raw_input("input moveSequence: ")
    exceptTrace = map(int, raw_input("input exceptTrace: ").strip().split())
    
    # startNode = 1
    # moveSequence = 'wwww'
    # exceptTrace = []
    
    # create search graph
    initWalkDict(exceptTrace)
    initAlleyDict(exceptTrace)
    
    # get result
    candidateList = getCandidateList(startNode, moveSequence)
    
    sortCadns = []
    for candidate in candidateList:
        walkWayList = doWalk(candidate)
        coachWayList = doCoach(candidate)
        alleyWayList = doAlley(candidate)
        sortCadns.append([len(walkWayList), len(coachWayList), len(alleyWayList), candidate])
        
    
    sortCadns.sort()
    
    sortCadns = sortCadns[::-1]
    
    print '***** candidateList *****'
    print 'startNode', startNode
    print 'moveSequence', moveSequence
    print 'exceptTrace', exceptTrace
    
    print 'len(candidateList)', len(sortCadns)
    for l in sortCadns:
        walkWayNum, coachWayNum, alleyWayNum, candidate = l
        out = 'n:%d\t#w:%d\t#c:%d\t#a:%d' % (candidate, walkWayNum, coachWayNum, alleyWayNum)
        print out
        
    for l in sortCadns:
        walkWayNum, coachWayNum, alleyWayNum, candidate = l
        
        print candidate,
    
