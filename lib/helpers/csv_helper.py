import csv

def read_csv(csv_route):
    """
    Recover all the information contained in the indicated csv file.

        :param csv_route: The route where csv file is stored
        :type cvs_route: str
        :return: A dictionary that stores all the information contained in the csv
        :rtype: dict
    """

    #Diccionary where information will be stored
    csv_info = {}

    # Open csv file in read mode
    with open(csv_route, 'r') as csvFile:
        reader = csv.reader(csvFile,delimiter=',')
        
        for row in reader:
            # If the dictionary is empty store the first row of information.
            # If not checks what IPs have the same MAC or the same O.S. to store in the csv
            if csv_info == {}:
                csv_info[row[0]] = {'MAC':{row[1]:[row[3]]},'name':row[2],'OS':[row[3]],'processor':row[4],'ram':row[5],'disk':row[6]}
            else:
                csv_info_keys = csv_info.keys()
                
                if row[0] in csv_info_keys:
                    csv_info_mac_keys = csv_info[row[0]]['MAC'].keys()
                    
                    if row[1] in csv_info_mac_keys:
                        csv_info[row[0]]['MAC'][row[1]].append(row[3])
                        csv_info[row[0]]['OS'].append(row[3])
                    elif row[3] in csv_info[row[0]]['OS']:
                        csv_info[row[0]]['MAC'][row[1]] = [row[3]]
                else:
                    csv_info[row[0]] = {'MAC':{row[1]:[row[3]]},'name':row[2],'OS':[row[3]],'processor':row[4],'ram':row[5],'disk':row[6]}

    #Close the csv file
    csvFile.close()
    
    # Return the information
    return csv_info
