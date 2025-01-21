FROM ubuntu:24.04

# Update and install dependencies
RUN apt-get update && \
    apt-get install -y python3 python3-pip python3-venv software-properties-common vim && \
    apt-add-repository --yes --update ppa:ansible/ansible

# Install ansible and collections
RUN apt install -y ansible

RUN pip3 install python-ilorest-library paramiko certifi --break-system-packages && \
    ansible-galaxy collection install hpe.ilo community.general

#Neovim setup
RUN apt install neovim git -y

RUN git clone https://github.com/NvChad/starter ~/.config/nvim $$ sed -i 's/vim\.uv/vim.loop/g' /root/.config/nvim/init.lua

