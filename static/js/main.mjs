import { dom } from "./dom.mjs";

function init(){
    let path = window.location.pathname
    if (path === '/'){
        dom.loadPlanets()
    }


}

init()