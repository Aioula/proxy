function NormalRequestPage() {
    return (
      <div className="flex items-center justify-center h-screen bg-green-50">
        <div className="text-center p-10 bg-white rounded shadow-lg border border-green-300">
          <h1 className="text-4xl font-bold text-green-600 mb-4">✅ Requête Autorisée</h1>
          <p className="text-gray-700">La requête a été considérée comme normale par le WAF.</p>
        </div>
      </div>
    );
  }
  export default NormalRequestPage;
  