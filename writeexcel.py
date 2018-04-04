import xlwt
from xlrd import open_workbook
from xlutils.copy import copy
global d
d = 0

def clear(line):
    linelist = line.split(' ')
    dict1 = {}

    def find(str, index):
        da = line.find(str, index)
        return da

    def findcon(start, end):
        linecon = line[start:end]
        listcon = linecon.split(' ')
        str1 = ''
        for j in listcon:
            str1 = str1 + j
        return str1

    def finddep(start, end):
        linedep = line[start:end]
        if 'depth:' in linedep:
            startd = linedep.find('depth:') + 6
            end = linedep.find(';', startd)
            depth = int(linedep[startd:end])
            return depth
        else:
            return None

    if 'alert ' in line:
        if linelist[0] == '#':
            dict1['level'] = 'alert'
            if linelist[2] == 'tcp':
                dict1['protocol'] = 6
            elif linelist[2] == 'udp':
                dict1['protocol'] = 17
            else:
                dict1['protocol'] = 0
            if linelist[3] == 'any':
                dict1['sip'] = str(0)
            elif linelist[3] == 'localhost':
                dict1['sip'] = str(9)
            else:
                dict1['sip'] = linelist[3]
            if linelist[4] == 'any':
                dict1['sport'] = 0
            else:
                dict1['sport'] = linelist[3]
            if linelist[6] == 'any':
                dict1['dip'] = str(0)
            elif linelist[6] == 'localhost':
                dict1['dip'] = str(9)
            else:
                dict1['dip'] = linelist[6]
            if linelist[7] == 'any':
                dict1['dport'] = 0
            else:
                if type(linelist[7]) == int:
                    dict1['dport'] = linelist[7]
                else:
                    dict1['dport'] = linelist[7]
        else:
            dict1['level'] = 'alert'
            if linelist[1] == 'tcp':
                dict1['protocol'] = 6
            elif linelist[1] == 'udp':
                dict1['protocol'] = 17
            else:
                dict1['protocol'] = 0
            if linelist[2] == 'any':
                dict1['sip'] = str(0)
            elif linelist[2] == 'localhost':
                dict1['sip'] = str(9)
            else:
                dict1['sip'] = linelist[3]
            if linelist[3] == 'any':
                dict1['sport'] = 0
            else:
                dict1['sport'] = linelist[3]
            if linelist[5] == 'any':
                dict1['dip'] = str(0)
            elif linelist[5] == 'localhost':
                dict1['dip'] = str(9)
            else:
                dict1['dip'] = linelist[6]
            if linelist[6] == 'any':
                dict1['dport'] = 0
            else:
                dict1['dport'] = linelist[6]

        idlist = ['1111203','1111201','1111202','1111204']
        idst = find('sid:',0) + 4
        iden = find(';',idst)
        id = line[idst:iden]
        if id in idlist:
            d = 1

        start = find('msg:', 0)
        print('start:',start)
        if start != -1:
            start = start +6
        end = find(';', start)
        print('end:',end)
        if end != -1:
            end = end - 1
        if start != -1 & end != -1:
            dict1['msg'] = line[start:end]
        else:
            dict1['msg'] = None

        count = line.count('content')
        dict1['content_num'] = count
        start1 = 0
        end1 = 0
        start2 = 0
        end2 = 0
        for i in range(count):
            start1 = find('content:', start1) + 10
            end1 = find('|";', start1)
            if i != count - 1:
                start2 = find('content:', end1) + 10
            else:
                start2 = len(line) - 1
            strcon = findcon(start1, end1)
            dict1['content' + str(i + 1)] = strcon
            dep = finddep(end1, start2)
            if dep:
                dict1['depth' + str(i + 1)] = dep

        count_byte = line.count('byte_test')
        if count_byte != 0:
            dict1['byte_test_num'] = count_byte
        start_byte = 0
        end_byte = 0
        for i in range(count_byte):
            start_byte = find('byte_test:', start_byte) + 10
            end_byte = find(';', start_byte)
            line_byte = line[start_byte:end_byte]
            line_byte = line_byte.strip()
            dict1['byte_test' + str(i + 1)] = line_byte

    else:
        pass
    if len(dict1) != 0:
        return dict1
    else:
        pass

def read(path1,sheet):
    file = open(path1,'r')
    lines = file.readlines()
    lines = set(lines)
    lines = list(lines)
    for i in lines:
        content = clear(i)
        if content != None:
            writer(content,sheet)


def writer(content,sheet):
    number = len(sheet.rows)
    content1 = zhuanhuan(content)
    for i in range(7):
        if i == 0:
            sheet.write(number,i,'omron')
        elif i == 1:
            sheet.write(number,i,content['dport'])
        elif i == 2:
            sheet.write(number,i,content['msg'])
        elif i == 3:
            sheet.write(number,i,content1)
        elif i == 5:
            sheet.write(number,i,'omron_test.pcap')

def zhuanhuan(content):
    str1 = '{'
    for key,value in content.items():
        str1 = str1 + str(key) + ":" + str(value) + ','
    str1 = str1 + '}'
    return str1

if __name__ == "__main__":
    path = '/home/gulu/下载/攻击检测规则.xlsx'
    path1 = '/home/gulu/下载/Quickdraw-Snort-master/omron.rules'
    rb = open_workbook(path)
    wb = copy(rb)
    sheet = wb.get_sheet(0)
    read(path1,sheet)
    wb.save(path)
