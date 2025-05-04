function BlockedPage() {
  return (
    <div className="flex items-center justify-center h-screen bg-red-50">
      <div className="text-center p-10 bg-white rounded shadow-lg border border-red-300">
        <h1 className="text-4xl font-bold text-red-600 mb-4">🚫 Accès Bloqué</h1>
        <p className="text-gray-700">Cette requête a été bloquée par le WAF pour des raisons de sécurité.</p>
        <p className="text-gray-500 text-sm mt-4">Si vous pensez que c’est une erreur, contactez l’administrateur.</p>
      </div>
    </div>
  );
}

export default BlockedPage;
