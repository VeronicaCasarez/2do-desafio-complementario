

const logout= document.getElementById("logout-button")
logout.addEventListener("click", async (event) => {
  event.preventDefault();

      const response = await fetch("/logout", {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
        },
      });
  
      if (response.ok) {
        window.location.href = "/"; // Redirige a la página de inicio de sesión
      } else {
        console.error("Error al cerrar sesión");
      }
 
  });
  