import csv

def read_csv(csv_route):
    """
    Recover all the information contained in the indicated csv file.

        :param csv_route: The route where csv file is stored
    """

    #Diccionary where information will be stored
    csv_info = {}

    with open(csv_route, 'r') as csvFile:
        reader = csv.reader(csvFile,delimiter=',')
        for row in reader:
            csv_info[row[0]] = {'MAC':row[1],'name':row[2],'OS':row[3],'processor':row[4],'ram':row[5],'disk':row[6]}

    csvFile.close()

    return csv_info
