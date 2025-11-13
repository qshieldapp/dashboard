import axios from "axios";

let apivar = "";
let secretvar = "";
let pubvar = "";

async function delete_key(){
    const apikey = document.getElementById('akdel').value;
    const secret = document.getElementById('spdel').value;

    const data = {
        api_key: apikey,
        secret_phrase: secret,
    };
    try{
        const res = await axios.post("https://quantumsure.onrender.com/api/quantumsure/delete", {
        data: data,
        });
        document.getElementById('keydel').innerHTML = `
            <h3 style="color: red;padding: 1%">Key has been deleted</h3>
        `;

    }
    catch (err){
        console.log(err);
        document.getElementById('keydel').innerHTML = `
            <h3 style="color: red;padding: 1%">Failed to delete this key. Make sure the secret phrase and api key are valid.</h3>
        `;
    }

}
window.delete_key = delete_key;



async function create_key(){
    document.getElementById('keycre2').innerHTML = `
            <h3 style="color: red;padding: 1%">Please wait while we generate your Keys..</h3>
        `;
    try{
        const res = await axios.post("https://quantumsure.onrender.com/api/quantumsure/create", {
        data: null,
        });
        console.log("Creation complete.");
        document.getElementById('keycre2').innerHTML = `
            <h3 style="color: red;padding: 1%">Key creation successful. Please copy and securely write the details on the right.</h3>
        `;
        pubvar = res.data.public_key;
        secretvar = res.data.secret_phrase;
        apivar = res.data.api_key;
        document.getElementById('keycre').style.visibility = 'visible';
    }
    catch (err){
        console.log(err);
        alert('something went wrong');
    }



}
window.create_key = create_key;

async function copy1(){
    try {
        const res = await navigator.clipboard.writeText(apivar);
    }
    catch (err){
        console.log(err);
    }
}
window.copy1 = copy1;


async function copy2(){
    try {
        const res = await navigator.clipboard.writeText(pubvar);
    }
    catch (err){
        console.log(err);
    }
}
window.copy2 = copy2;


async function copy3(){
    try {
        const res = await navigator.clipboard.writeText(secretvar);
    }
    catch (err){
        console.log(err);
    }
}
window.copy3 = copy3;

async function to_kyber(){
    window.open("https://pq-crystals.org/kyber/", '_blank');
}
window.to_kyber = to_kyber;


async function to_fernet(){
    window.open('https://cryptography.io/en/latest/fernet/', '_blank');
}
window.to_fernet = to_fernet;
