# File path
file_path = 'password.txt'

# Step 1: Open the file in read mode
with open(file_path, 'r') as file:
    # Step 2: Read the content of the file
    content = file.read()
    # Alternatively, you can read the file line by line using the readlines() method:
    # lines = file.readlines()

# Step 3: The file is automatically closed after the 'with' block

# Now you can work with the 'content' variable containing the file's content
print(content)
