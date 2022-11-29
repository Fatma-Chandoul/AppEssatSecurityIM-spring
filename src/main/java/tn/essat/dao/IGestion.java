package tn.essat.dao;

import java.util.List;

import tn.essat.model.Produit;

public interface IGestion {
	
	public List<Produit> getAllProduit();
	public void addProduit(Produit p);
	public void deleteProduit(int id);

}
