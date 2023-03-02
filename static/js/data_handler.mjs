export let dataHandler =
{
    _data: {},
    _api_get: function (url, callback) {
        // it is not called from outside
        // loads data from API, parses it and calls the callback with it

        fetch(url, {
            method: 'GET',
        })
        .then(response => response.json())  // parse the response as JSON
        .then(json_response => callback(json_response));  // Call the `callback` with the returned object
        },
    getPlanets: function (url, callback){
        this._api_get(url, (response) => {
            this._data = response;
            callback(response);

    })
    },
    getResident: function (url, callback) {
            this._api_get(url, (response)=> {
                this._data = response;
                console.log(response)
                callback(response);})

    }

};

function getPlanets() {
    fetch(url, {
            method: 'GET'
        })
        .then(response => console.log(res));  // parse the response as JSON
        };
