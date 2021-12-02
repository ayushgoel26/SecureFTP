import os


class FileTransfer:
    def __init__(self, directory_folder):
        jf = None
        self.path = os.getcwd() + directory_folder

    # List files in local directory
    def local_files(self):
        l_files = os.listdir(self.path)  # gets content of folder
        print("File Directory: " + self.path)
        if not l_files:
            print("The Directory is empty")
            return
        # prints only files in the folder
        for file in l_files:
            file_path = os.path.join(self.path, file)
            if os.path.isfile(file_path):
                print("\t" + file)
        return l_files
