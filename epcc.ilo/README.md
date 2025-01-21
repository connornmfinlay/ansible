# epcc.ilo

Git repo used for interacting with ILOs and BMCs

## Useful Commands

sudo docker build -t ansible:2.17 .

sudo docker run -dit --name ansible-container --network host -v $(pwd):/ansible/playbooks ansible:2.17

ansible-playbook -i inventory.ini playbooks/ilo_interface.yaml -e @secrets.yaml -e vars/vars.yaml --ask-vault-pass
