let licenses = [
    {
        "license": {
            "id": "MIT"
        }
    },
    {
        "license": {
            "id": "MIT2"
        }
    },
];
let a = [];
for (let i of licenses) {
    if (a.indexOf(i.id) === -1) a.push(i.license.id);
}
console.log(a);