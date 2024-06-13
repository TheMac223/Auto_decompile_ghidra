import os

common_code = ''

def extract_before_marker(file_content, marker):
    marker_idx = file_content.find(marker)
    global common_code
    if marker_idx != -1:
        common_code = file_content[:marker_idx]

def extract_between(file_content, start_marker, end_marker):
    start_idx = file_content.find(start_marker)
    end_idx = file_content.find(end_marker, start_idx)

    if start_idx != -1 and end_idx != -1:
        return common_code +"\n"+ file_content[start_idx:end_idx + len(end_marker)]
    return None

def save_to_file(content, filename):
    with open(filename, 'w') as file:
        file.write(content)

def find_cwe_c_files(base_dir):
    cwe_c_files = []

    # base_dir 내부의 모든 디렉토리를 탐색
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.startswith('CWE') and file.endswith('.c'):
                cwe_c_files.append(os.path.join(root, file))
    
    return cwe_c_files

def save_files_with_new_names(filename,content):
        
        with open(filename, 'w') as file:
            file.write(content)
            print(f"Saved: {filename}")


def main():
    files = find_cwe_c_files("./bof")
    for file_ in files:
        with open(file_, 'r') as file:
            c_code = file.read()
            
        if c_code:

            extract_before_marker(c_code, '#ifndef OMITBAD') # common code

            # BAD
            omitbad_content = extract_between(c_code, '#ifndef OMITBAD', '#endif')
            if omitbad_content:
                save_files_with_new_names(file.name[:-2]+"_omitbad.c",omitbad_content)

            # GOOD
            omitgood_content = extract_between(c_code, '#ifndef OMITGOOD', '#endif')
            if omitgood_content:
                save_files_with_new_names(file.name[:-2]+"_omitgood.c",omitgood_content)

if __name__ == "__main__":
    main()
