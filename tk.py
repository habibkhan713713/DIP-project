
import tkinter as tk
from tkinter import filedialog, messagebox
import cv2
import tkinter.ttk as ttk
import pyperclip
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64



import os

def generate_aes_key():
    return os.urandom(32)  # 256 bits for AES-256

def generate_iv():
    return os.urandom(16)  # 128 bits for AES

def encrypt_data(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return ciphertext

def decrypt_data(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data


SIZE_BITS = 64  # Use 64 bits to represent the size


def extract_data_size(frame):
    # Extract size information from LSBs of blue channel
    size_binary = ''.join([str(frame[i, 0, 0] & 0x01) for i in range(SIZE_BITS)])

    # Convert binary string to integer
    data_size = int(size_binary, 2)

    return data_size


def extract_data_from_frame(frame, data_size, bytes_read):
    extracted_data = bytearray()

    height, width, _ = frame.shape

    for i in range(height):
        for j in range(width):
            index = i * width + j

            if index < data_size:
                # Extract the 3 least significant bits from blue, green, and red channels
                blue_bits = (frame[i, j, 0] & 0b00000111)
                green_bits = (frame[i, j, 1] & 0b00000111) << 3
                red_bits = (frame[i, j, 2] & 0b00000111) << 6

                # Combine the bits to form a byte
                data_byte = blue_bits | green_bits | red_bits

                # Append the byte to the extracted data
                extracted_data.append(data_byte & 0xFF)  # Ensure the value is within the valid byte range

                bytes_read += 1

    return bytes(extracted_data)


def hide_data_size(frame, data_size):
    # Encode data size using binary format
    size_binary = format(data_size, '0' + str(SIZE_BITS) + 'b')

    # Hide size information in LSBs of blue channel
    for i in range(SIZE_BITS):
        frame[i, 0, 0] = (frame[i, 0, 0] & 0xFE) | int(size_binary[i])

    return frame


def manipulate_frame(frame, data_chunk):
    if data_chunk:
        # Iterate over each pixel in the frame
        for i in range(frame.shape[0]):
            for j in range(frame.shape[1]):
                # Calculate the index for data_chunk
                index = i * frame.shape[1] + j

                # Ensure the index is within the bounds of data_chunk
                if index < len(data_chunk):
                    # Extract the 3 least significant bits for blue channel
                    blue_bits = data_chunk[index] & 0b00000111

                    # Extract the 3 least significant bits for green channel
                    green_bits = (data_chunk[index] >> 3) & 0b00000111

                    # Extract the 2 least significant bits for red channel
                    red_bits = (data_chunk[index] >> 6) & 0b00000011

                    # Update the blue, green, and red channels with the bits
                    frame[i, j, 0] = (frame[i, j, 0] & 0b11111000) | blue_bits
                    frame[i, j, 1] = (frame[i, j, 1] & 0b11111000) | green_bits
                    frame[i, j, 2] = (frame[i, j, 2] & 0b11111100) | red_bits

        return frame


def process_video(input_video_path, output_video_path, data_size, data, progress_var, encoding_status_label):
    # Open the video file
    video_capture = cv2.VideoCapture(input_video_path)

    # Get the video properties
    fps = int(video_capture.get(cv2.CAP_PROP_FPS))
    width = int(video_capture.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(video_capture.get(cv2.CAP_PROP_FRAME_HEIGHT))

    # Get the total number of frames
    total_frames = int(video_capture.get(cv2.CAP_PROP_FRAME_COUNT))

    video_size = total_frames * width * height

    if data_size > video_size:
        print("Input data too big to be hidden inside the video")
        exit()

    # Create VideoWriter object to save the manipulated frames
    fourcc = cv2.VideoWriter_fourcc(*'FFV1')  # Add the bitrate here, e.g., 'HFYU1M'
    video_writer = cv2.VideoWriter(output_video_path, fourcc, fps, (width, height), isColor=True)

    frame_count = 0
    frame_size = width * height

    # Set maximum value for progress bar
    progress_var["maximum"] = total_frames

    while True:
        # Read a frame from the video
        ret, frame = video_capture.read()

        # Break the loop if we reach the end of the video
        if not ret:
            break

        if frame_count == 0:
            # Manipulate the first frame to hide data size
            frame = hide_data_size(frame, data_size)
        else:
            # Extract the corresponding chunk of data
            start_index = (frame_count - 1) * frame_size
            end_index = start_index + frame_size
            data_chunk = data[start_index:end_index]
            if data_chunk:
                # Manipulate the frame with the data chunk
                frame = manipulate_frame(frame, data_chunk)

        # Write the manipulated frame to the output video file
        video_writer.write(frame)
        frame_count += 1

        # Update the progress bar
        progress_var.step(1)

        # Update encoding status label
        encoding_status_label.config(text=f"Encoding in progress - Frame {frame_count}/{total_frames}")

        # Update GUI
        encoding_status_label.update_idletasks()
        progress_var.update_idletasks()

    # Release resources
    video_capture.release()
    video_writer.release()
    cv2.destroyAllWindows()



#############  Tkinter  #################




class VideoEncoderApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Video Encoder with Hidden Data")
        self.master.configure(bg="#e1f2ed") 

        # Variables
        self.input_video_path = tk.StringVar()
        self.output_video_path = "output.avi"
        self.input_file_path = tk.StringVar()
        self.encryption = tk.StringVar()
        self.init_vect = tk.StringVar()
        self.encoding_mode = 0

        # Create frames
        self.main_frame = tk.Frame(master)
        self.main_frame = tk.Frame(master, bg="#e1f2ed")

        # Set up main frame
        self.setup_main_frame()

        # Set window size based on screen size
        screen_width = master.winfo_screenwidth()
        screen_height = master.winfo_screenheight()
        master.geometry(f"{screen_width}x{screen_height}+0+0")  # Fullscreen
    
    def decode_video(self):
        try:
            input_video_path = self.input_video_path.get()
            output_file_path = "extracted_data"  # Replace with the desired output file path
            print(self.encryption.get() , self.init_vect.get())
            # Open the video file
            video_capture = cv2.VideoCapture(input_video_path)

            frame_count = 0
            bytes_read = 0

            while True:
                # Read a frame from the video
                ret, frame = video_capture.read()
                frame_size = frame.shape[0] * frame.shape[1]

                # Break the loop if we reach the end of the video or have read all hidden data
                if not ret:
                    break

                if frame_count == 0:
                    # Extract data size from the first frame
                    data_size = extract_data_size(frame)
                    print(f"Data size in bytes: {data_size}")

                else:
                    # Extract data from the frames
                    extracted_data = extract_data_from_frame(frame, data_size, bytes_read)
                    data_size -= frame_size

                    # Create a file and write the extracted data
                    with open(output_file_path, 'ab') as output_file:
                        output_file.write(extracted_data)
                        bytes_read += len(extracted_data)

                    print(f"Processed frame {frame_count} - Bytes read: {bytes_read}")

                    # Update progress label
                    self.progress_label.config(text=f"Decoding progress: {bytes_read} bytes")
                    self.master.update_idletasks()

                if data_size <= 0:
                    break

                frame_count += 1

            # Release resources
            video_capture.release()
            cv2.destroyAllWindows()

            with open("extracted_data", 'r+b') as file:
            # Read the content of the file
                file_content = file.read()

                # Modify the content as needed
                encryption = self.encryption.get()
                init_vect = self.init_vect.get()

                encryption = base64.b64decode(encryption.encode('utf-8'))
                init_vect = base64.b64decode(init_vect.encode('utf-8')) 
                modified_content = decrypt_data(file_content, encryption ,  init_vect)

                # Move the file pointer to the beginning of the file
                file.seek(0)

                # Truncate the file (remove its contents)
                file.truncate()

                # Write the modified content back to the file
                file.write(modified_content)

            messagebox.showinfo("Success", "Video decoded successfully!")

        except FileNotFoundError:
            messagebox.showerror("Error", f"File '{input_video_path}' not found.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")


    def setup_main_frame(self):
        # Clear the main frame
        for widget in self.main_frame.winfo_children():
            widget.destroy()

        if self.encoding_mode == 0:
            # Display encoding widgets
            tk.Button(self.main_frame, text="Switch to Encoding", command=lambda : self.switch_frame(0), font=25,foreground= "black" if self.encoding_mode == 0 else "white" , bg="#2dad87" if self.encoding_mode == 0 else "black", width=20, height=2 ,activeforeground="white" if self.encoding_mode == 0 else "black"  , activebackground = "#2dad87" if self.encoding_mode == 0 else "black" ).grid(row=0,
                                                                                                                   column=0,
                                                                                                                   padx=(0,0), pady=(20,80))
            tk.Button(self.main_frame, text="Switch to Decoding", command=lambda :self.switch_frame(1), font=25, width=20, bg="#2dad87" if self.encoding_mode == 1 else "black",foreground = "black" if self.encoding_mode == 1 else "white",activeforeground="white" if self.encoding_mode == 1 else "black"  , activebackground = "#2dad87" if self.encoding_mode == 1 else "white",  height=2).grid(row=0,
                                                                                                                   column=1,
                                                                                                                   padx=(0,0), pady=(20,80))
            tk.Button(self.main_frame, text="Generate keys", command=lambda :self.switch_frame(2), font=25, width=20,bg="#2dad87" if self.encoding_mode == 2 else "black",foreground= "black" if self.encoding_mode == 2 else "white",activeforeground="white" if self.encoding_mode == 2 else "black"  , activebackground = "#2dad87" if self.encoding_mode == 2 else "white"  , height=2).grid(row=0,
                                                                                                                   column=2,
                                                                                                                   padx=(0,0), pady=(20,80)) 

            
            

            tk.Label(self.main_frame, font=25,bg="#e1f2ed", text="Enter video path to be encoded :").grid(row=1, column=0, sticky="e", padx=120,
                                                                                 pady=20)
            tk.Label(self.main_frame, font=25,bg="#e1f2ed", text="File to Hide :").grid(row=2, column=0, sticky="e", padx=120, pady=20)

            tk.Label(self.main_frame, font=25,bg="#e1f2ed", text="Enter Encryption key for Encoding :").grid(row=4, column=0, sticky="e", padx=120,
                                                                                 pady=20)
            tk.Label(self.main_frame, font=25,bg="#e1f2ed", text="Enter Initialization vector :").grid(row=5, column=0, sticky="e", padx=120,
                                                                                          pady=20)

            tk.Entry(self.main_frame, textvariable=self.input_video_path, width=40, font=25).grid(row=1, column=1, padx=5, pady=5)
            tk.Entry(self.main_frame , textvariable= self.encryption ,width=40, font=25).grid(row=4, column=1, padx=5, pady=5)
            tk.Entry(self.main_frame, textvariable=self.input_file_path, width=40, font=25).grid(row=2, column=1, padx=5, pady=5)
            
            tk.Entry(self.main_frame, textvariable=self.init_vect, width=40, font=25).grid(row=5, column=1, padx=5, pady=5)

             
            tk.Button(self.main_frame, text="Browse", command=self.browse_input_video, foreground=  "white" , bg="black" , activebackground= "white" , activeforeground= "black", font=25, width=10, height=1).grid(row=1,
                                                                                                                   column=2,
                                                                                                                   padx=25, pady=20)
            tk.Button(self.main_frame, text="Browse", command=self.browse_input_file, width=10, font=25, foreground=  "white" , bg="black" , activebackground= "white" , activeforeground= "black", height=1).grid(row=2,
                                                                                                                   column=2,
                                                                                                                   padx=25, pady=20)

            tk.Button(self.main_frame, text="Encode Video", command=self.encode_video, foreground=  "white" , bg="black" , activebackground= "white" , activeforeground= "black", font=25, width=12, height=2).grid(row=6,
                                                                                                                   column=1,
                                                                                                                   pady=20)

                                                                                      

            self.encoding_status_label = tk.Label(self.main_frame, text="", font=25)
            self.encoding_status_label.grid(row=7, column=1, pady=10)
        elif self.encoding_mode == 1:
                    # Display decoding widgets
            
            tk.Button(self.main_frame, text="Switch to Encoding", command=lambda : self.switch_frame(0), font=25,foreground= "black" if self.encoding_mode == 0 else "white" , bg="#2dad87" if self.encoding_mode == 0 else "black", width=20, height=2 ,activeforeground="white" if self.encoding_mode == 0 else "black"  , activebackground = "#2dad87" if self.encoding_mode == 0 else "white" ).grid(row=0,
                                                                                                                   column=0,
                                                                                                                   padx=25, pady=(20,80))
            tk.Button(self.main_frame, text="Switch to Decoding", command=lambda :self.switch_frame(1), font=25, width=20, bg="#2dad87" if self.encoding_mode == 1 else "black",foreground = "black" if self.encoding_mode == 1 else "white",activeforeground="white" if self.encoding_mode == 1 else "black"  , activebackground = "#2dad87" if self.encoding_mode == 1 else "white",  height=2).grid(row=0,
                                                                                                                   column=1,
                                                                                                                   padx=25, pady=(20,80))
            tk.Button(self.main_frame, text="Generate keys", command=lambda :self.switch_frame(2), font=25, width=20,bg="#2dad87" if self.encoding_mode == 2 else "black",foreground= "black" if self.encoding_mode == 2 else "white",activeforeground="white" if self.encoding_mode == 2 else "black"  , activebackground = "#2dad87" if self.encoding_mode == 2 else "white"  , height=2).grid(row=0,
                                                                                                                   column=2,
                                                                                                                   padx=25, pady=(20,80)) 


            tk.Label(self.main_frame, font=25,bg="#e1f2ed", text="Select file to be decoded:").grid(row=1, column=0, sticky="e", padx=120,
                                                                                    pady=20)
            tk.Entry(self.main_frame, textvariable=self.input_video_path, width=40, font=25).grid(row=1, column=1, padx=5,
                                                                                                pady=5)
            
        
            tk.Button(self.main_frame, text="Browse", command=self.browse_input_video , foreground=  "white" , bg="black" , activebackground= "white" , activeforeground= "black", font=25, width=10, height=1).grid(
                row=1, column=2, padx=25, pady=20)
            
            tk.Label(self.main_frame, font=25,bg="#e1f2ed", text="Enter your Encryption key for decoding :").grid(row=2, column=0, sticky="e", padx=120,
                                                                                    pady=20)
            tk.Entry(self.main_frame, textvariable=self.encryption, width=40, font=25).grid(row=2, column=1, padx=5,
                                                                                                pady=20)
            
            tk.Label(self.main_frame, font=25,bg="#e1f2ed", text="Enter Initialization vector :").grid(row=3, column=0, sticky="e", padx=120,
                                                                                    pady=20)
            tk.Entry(self.main_frame, textvariable=self.init_vect, width=40, font=25).grid(row=3, column=1, padx=5,
                                                                                                pady=20)


            tk.Button(self.main_frame, text="Decode Video" , foreground=  "white" , bg="black" , activebackground= "white" , activeforeground= "black", command=self.decode_video, font=25, width=12, height=2).grid(
                row=4, column=1, pady=20 , padx=20 )
            
            self.progress_label = tk.Label(self.main_frame, font=25, text="")
            self.progress_label.grid(row=5, column=1, pady=10)

        
        elif self.encoding_mode ==2 :
            self.generate_keys()
                

        self.main_frame.pack()

    def browse_input_video(self):
        file_path = filedialog.askopenfilename()
        self.input_video_path.set(file_path)

    def browse_input_file(self):
        file_path = filedialog.askopenfilename()
        self.input_file_path.set(file_path)

    def encode_video(self):
        try:
            input_video_path = self.input_video_path.get()
            output_video_path = self.output_video_path
            input_file_path = self.input_file_path.get()

            with open(input_file_path, 'rb') as input_file:
                data_to_hide = input_file.read()
                encryption = self.encryption.get()
                init_vect = self.init_vect.get()

                # Encode the strings to bytes using UTF-8 encoding
                encryption = base64.b64decode(encryption.encode('utf-8'))
                init_vect = base64.b64decode(init_vect.encode('utf-8')) 
                
                data_to_hide = encrypt_data(data_to_hide , encryption , init_vect)

            data_size_to_hide = len(data_to_hide)

            progress_var = tk.DoubleVar(value=0.0)
            progress_bar = ttk.Progressbar(self.main_frame, orient="horizontal", length=200, mode="determinate", variable=progress_var, maximum=100.0)

            process_video(input_video_path, output_video_path, data_size_to_hide, data_to_hide, progress_bar,
                          self.encoding_status_label)

            messagebox.showinfo("Success", "Video encoded successfully!")

        except FileNotFoundError:
            messagebox.showerror("Error", f"File '{input_file_path}' not found.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def switch_frame(self , val):
        self.main_frame.pack_forget()
        if val == 0 :
         self.encoding_mode = 0
         self.setup_main_frame()
        elif val==1 :
         self.encoding_mode = 1 
         self.setup_decoding_frame()
        elif val ==2 :
            self.encoding_mode = 2
            self.generate_keys()
        self.main_frame.pack()

    def setup_decoding_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

        # Display decoding widgets
        tk.Button(self.main_frame, text="Switch to Encoding", command=lambda : self.switch_frame(0), font=25,foreground= "black" if self.encoding_mode == 0 else "white" , bg="#2dad87" if self.encoding_mode == 0 else "black", width=20, height=2 ,activeforeground="white" if self.encoding_mode == 0 else "black"  , activebackground = "black" if self.encoding_mode == 0 else "white" ).grid(row=0,
                                                                                                                   column=0,
                                                                                                                   padx=25, pady=(20,80))
        tk.Button(self.main_frame, text="Switch to Decoding", command=lambda :self.switch_frame(1), font=25, width=20, bg="#2dad87" if self.encoding_mode == 1 else "black",foreground = "black" if self.encoding_mode == 1 else "white",activeforeground="white" if self.encoding_mode == 1 else "black"  , activebackground = "#2dad87" if self.encoding_mode == 1 else "white",  height=2).grid(row=0,
                                                                                                                   column=1,
                                                                                                                   padx=25, pady=(20,80))
        tk.Button(self.main_frame, text="Generate keys", command=lambda :self.switch_frame(2), font=25, width=20,bg="#2dad87" if self.encoding_mode == 2 else "black",foreground= "black" if self.encoding_mode == 2 else "white",activeforeground="white" if self.encoding_mode == 2 else "black"  , activebackground = "#2dad87" if self.encoding_mode == 2 else "white"  , height=2).grid(row=0,
                                                                                                                   column=2,
                                                                                                                   padx=25, pady=(20,80)) 


        tk.Label(self.main_frame, font=25,bg="#e1f2ed", text="Select file to be decoded:").grid(row=1, column=0, sticky="e", padx=120,
                                                                                    pady=20)
        tk.Entry(self.main_frame, textvariable=self.input_video_path, width=40, font=25).grid(row=1, column=1, padx=5,
                                                                                                pady=5)
            
        
        tk.Button(self.main_frame, text="Browse", command=self.browse_input_video , foreground=  "white" , bg="black" , activebackground= "white" , activeforeground= "black", font=25, width=10, height=1).grid(
                row=1, column=2, padx=25, pady=20)
            
        tk.Label(self.main_frame, font=25,bg="#e1f2ed", text="Enter your Encryption key for decoding :").grid(row=2, column=0, sticky="e", padx=120,
                                                                                    pady=20)
        tk.Entry(self.main_frame, textvariable=self.encryption, width=40, font=25).grid(row=2, column=1, padx=5,
                                                                                                pady=20)
            
        tk.Label(self.main_frame, font=25,bg="#e1f2ed", text="Enter Initialization vector :").grid(row=3, column=0, sticky="e", padx=120,
                                                                                    pady=20)
        tk.Entry(self.main_frame, textvariable=self.init_vect, width=40, font=25).grid(row=3, column=1, padx=5,
                                                                                                pady=20)


        tk.Button(self.main_frame, text="Decode Video" , foreground=  "white" , bg="black" , activebackground= "white" , activeforeground= "black", command=self.decode_video, font=25, width=12, height=2).grid(
                row=4, column=1, pady=20 , padx=20 )
            
        self.progress_label = tk.Label(self.main_frame, font=25, text="")
        self.progress_label.grid(row=5, column=1, pady=10)


        self.main_frame.pack()

    def copy_to_clipboard(self , text_to_copy):
         pyperclip.copy(text_to_copy)    


    def generate_keys(self):
        

        # message = f"Private Key:\n{private_key_bytes.decode()}\n\nPublic Key:\n{public_key_bytes.decode()}"
        # messagebox.showinfo("Generated Keys", message)

        
        for widget in self.main_frame.winfo_children():
            widget.destroy()

        tk.Button(self.main_frame, text="Switch to Encoding", command=lambda : self.switch_frame(0), font=25,foreground= "black" if self.encoding_mode == 0 else "white" , bg="#2dad87" if self.encoding_mode == 0 else "black", width=20, height=2 ,activeforeground="white" if self.encoding_mode == 0 else "black"  , activebackground = "white" if self.encoding_mode == 0 else "white" ).grid(row=0,
                                                                                                                   column=0,
                                                                                                                   padx=25, pady=(20,80))
        tk.Button(self.main_frame, text="Switch to Decoding", command=lambda :self.switch_frame(1), font=25, width=20, bg="#2dad87" if self.encoding_mode == 1 else "black",foreground = "black" if self.encoding_mode == 1 else "white",activeforeground="white" if self.encoding_mode == 1 else "black"  , activebackground = "#2dad87" if self.encoding_mode == 1 else "white",  height=2).grid(row=0,
                                                                                                                   column=1,
                                                                                                                   padx=25, pady=(20,80))
        tk.Button(self.main_frame, text="Generate keys", command=lambda :self.switch_frame(2), font=25, width=20,bg="#2dad87" if self.encoding_mode == 2 else "black",foreground= "black" if self.encoding_mode == 2 else "white",activeforeground="white" if self.encoding_mode == 2 else "black"  , activebackground = "#2dad87" if self.encoding_mode == 2 else "white"  , height=2).grid(row=0,
                                                                                                                   column=2,
                                                                                                                   padx=25, pady=(20,80)) 


            

        # Display decoding widgets
        tk.Label(self.main_frame, font=25,bg="#e1f2ed", text="Encryption Key :").grid(row=1, column=0, sticky="e", padx=120,
                                                                                pady=20)
        tk.Entry(self.main_frame, textvariable= self.encryption, width=40, font=25).grid(row=1, column=1, padx=5,
        
                                                                                            pady=5)
        
        tk.Button(self.main_frame, text="Copy", foreground=  "white" , bg="black" , activebackground= "white" , activeforeground= "black", command=lambda : self.copy_to_clipboard(self.encryption.get()), font=25,
                width=8, height=1).grid(row=1, column=2, pady=10, padx=10, sticky='w')

        tk.Label(self.main_frame, font=25,bg="#e1f2ed", text="Initialization Vector :").grid(row=2, column=0, sticky="e", padx=120,
                                                                                pady=20)
        tk.Entry(self.main_frame, textvariable = self.init_vect, width=40, font=25).grid(row=2, column=1, padx=5,pady=5)

        tk.Button(self.main_frame , foreground=  "white" , bg="black" , activebackground= "white" , activeforeground= "black", text="Copy", command=lambda : self.copy_to_clipboard(self.init_vect.get()), font=25,
                width=8, height=1).grid(row=2, column=2, pady=10, padx=10, sticky='w')   
                                                                                        
        tk.Button(self.main_frame , foreground=  "white" , bg="black" , activebackground= "white" , activeforeground= "black", text="Generate", command=self.generate_key, font=25,
                width=20, height=2).grid(row=3, column=1, pady=30, padx=50, sticky='w')   
                


        

        self.main_frame.pack()
    def generate_key(self):
    # Generate AES key and IV
        aes_key = generate_aes_key()
        iv = generate_iv()

      
        # Set key and IV in tkinter variables
        print(len(aes_key) , len(iv))

        aes_key = base64.b64encode(aes_key).decode('utf-8')
        iv= base64.b64encode(iv).decode('utf-8')

        
        self.encryption.set(aes_key)
        self.init_vect.set(iv)

        # Write key and IV to a file
        with open("key_and_iv.txt", 'w') as file:
            file.write("Encryption Key : ")
            file.write(aes_key)
            file.write('\n')
            file.write("initialization vector : ")
            file.write(iv)


if __name__ == "__main__":
    root = tk.Tk()
    app = VideoEncoderApp(root)
    root.mainloop()
