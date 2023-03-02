import { dataHandler } from "./data_handler.mjs";

export let dom = {
    loadPlanets: function (){
        dataHandler.getPlanets('https://swapi.dev/api/planets/',function(planets){
            dom.showPlanets(planets);
        });
    },
    loadResidents: function(residents){
    for (let residente of residents){
        let resident = residente.toString()
        dataHandler.getResident(resident, function (singleResident) {
            dom.showResident(singleResident);})}},


    loadNextPlanets: function (){
        let nextButton = document.getElementById('next');
        let link = nextButton.getAttribute('value');
        if (link != null){
            dataHandler.getPlanets(link, function(planets){
            dom.showPlanets(planets);
        })

        };
    },
    loadPreviousPlanets: function (){
        let previousButton = document.getElementById('previus');
        let link = previousButton.getAttribute('value');
        if (link != null){
            dataHandler.getPlanets(link, function (planets) {
            dom.showPlanets(planets);
        })
        };

    },
    formatNumber: function(num) {
        return num.toString().replace(/(\d)(?=(\d{3})+(?!\d))/g, '$1,')},

    showResident: function(singleResident){

        let residentData = [];
        console.log(singleResident);
        let name = singleResident.name;
        let height = singleResident.height;
        let mass = singleResident.mass;
        let hair = singleResident.hair_color;
        let eyes = singleResident.eye_color;
        let year = singleResident.birth_year;
        let gender = singleResident.gender;
        let skin = singleResident.skin_color;

        residentData += `
                <tr>
                    <td>${name}</td>   
                    <td>${height}</td>
                    <td>${mass}</td>
                    <td>${hair}</td>
                    <td>${skin}</td>
                    <td>${eyes}</td>
                    <td>${year}</td>
                    <td>${gender}</td>
                </tr>                
                `
        let modal = document.getElementById('modalrows');
        modal.insertAdjacentHTML('beforeend', residentData)
    },


    finalResidents: function(){
        let modal = document.getElementById("modalrows");
        modal.innerHTML = '';
        let links = this.getAttribute('value');
        let linksArray = links.split(',');
        dom.loadResidents(linksArray)

    },

    modalTitle: function(){
        let planet = this.getAttribute('data-planet');
        let header = document.getElementById('modalHeader');
        let text = `<h5 style="text-align: left">Residents of ${planet}</h5>`;
        header.insertAdjacentHTML('afterbegin', text)


    },

    showPlanets: function(planets) {
        let next = planets.next;
        let previous = planets.previous;
        let planetList = '';
        let planetsData = planets.results;
        console.log(planetsData);
        for (let planet of planetsData) {
            let planet_name = planet.name;
            let diameter = planet.diameter;
            let climate = planet.climate;
            let terrain = planet.terrain;
            let surface_water = planet.surface_water;
            let population = planet.population;
            let residents = planet.residents.length;
            let residentsData = planet.residents
            // console.log(residentsData);

            planetList += `
                <tr>
                    <td>${planet_name}</td>
                    <td>${dom.formatNumber(diameter)}</td>
                    <td>${climate}</td>
                    <td>${terrain}</td>
                    <td>${surface_water}</td>
                    <td>${dom.formatNumber(population)}</td>
                    <td>
                        ${ residents > 0 ? 
                            `<button class="button residentsModal" value="${residentsData}" data-planet="${planet_name}">${residents}</button>` :
                            `No known residents`}         
                            
                    </td>
                </tr>
            `
        }
        document.getElementById('rows').innerHTML = '';
        let dataRow = document.getElementById('rows')
        dataRow.insertAdjacentHTML('beforeend', planetList);

        let previousButton = document.getElementById('previus');
        previousButton.setAttribute('value', previous)
        let nextButton = document.getElementById('next');
        nextButton.setAttribute('value', next)

        previousButton.addEventListener('click', dom.loadPreviousPlanets);
        nextButton.addEventListener('click', dom.loadNextPlanets);

        let modalButtons = document.querySelectorAll('.residentsModal');
        for ( let button of modalButtons){
            button.addEventListener('click', dom.openModal)
            button.addEventListener('click', dom.finalResidents);
            button.addEventListener('click', dom.modalTitle)
        }
        let closeButton = document.querySelector('.close');
        closeButton.addEventListener('click', dom.closeModal);

        window.addEventListener('click', dom.outsideClick);



    },

    openModal: function (){
        let modal = document.getElementById('mymodal');
        modal.style.display = 'block';},

    closeModal: function () {
        let modal = document.getElementById('mymodal');
        modal.style.display = 'none';
    },
    outsideClick: function (e) {
        let modal = document.getElementById('mymodal');
        if (e.target === modal) {
            modal.style.display = 'none';}
    },

}