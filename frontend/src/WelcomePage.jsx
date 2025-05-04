function WelcomePage() {
  return (
    <div className="flex items-center justify-center h-screen bg-blue-100">
      <div className="text-center p-10 bg-white rounded shadow-lg">
        <h1 className="text-4xl font-bold text-blue-600 mb-4">
          🚀 Bienvenue sur le WAF
        </h1>
        <p className="text-gray-700">Ceci est une page d'accueil sécurisée </p>
      </div>
    </div>
  );
}

export default WelcomePage;
