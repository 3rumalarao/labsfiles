from PyPDF2 import PdfReader
import PyPDF2
import pandas as pd
from docx import Document

def extract_data_from_pdf(file_path):
    with open(file_path, 'rb') as file:
        reader = PyPDF2.PdfReader(file)
        text = ''
        for page_num in range(reader.pages):
            page = reader.pages[page_num]
            text += page.extract_text()
    return text

def extract_text_from_excel(file_path):
    df = pd.read_excel(file_path)
    return df.to_string()

def extract_text_from_word(file_path):
    doc = Document(file_path)
    text = ''
    for para in doc.paragraphs:
        text += para.text + '\n'
    return text

def extract_text_from_txt(file_path):
    with open(file_path, 'r') as file:
        text = file.read()
    return text
