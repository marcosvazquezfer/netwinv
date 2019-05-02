import csv

def read_csv(csv_route):

    csv_info = {}

    with open(csv_route, 'r') as csvFile:
        reader = csv.reader(csvFile,delimiter=',')
        for row in reader:
            csv_info[row[0]] = {'MAC':row[1],'nombre':row[2],'SO':row[3],'procesador':row[4],'ram':row[5],'disco':row[6]}

    csvFile.close()

    return csv_info
