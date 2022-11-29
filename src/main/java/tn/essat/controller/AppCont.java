package tn.essat.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import tn.essat.dao.IGestion;
import tn.essat.model.Produit;

@Controller
public class AppCont {
	@Autowired
	IGestion gest;

	public void setGest(IGestion gest) {
		this.gest = gest;
	}

	@GetMapping("/produits")
	public String f1(Model m) {
		List<Produit> liste = gest.getAllProduit();
		m.addAttribute("liste", liste);
		return "page1";

	}


	@GetMapping("/ajout")
	public String f2(Model m) {
		Produit p = new Produit();
		m.addAttribute("p", p);
		return "page2";
	}

	@PostMapping("/save")
	public String f3(Model m, @ModelAttribute("prods") Produit p) {
		gest.addProduit(p);
		return "redirect:/produits";

	}
	
	@GetMapping("/deleteProduit/{id}")
	public String f4(Model m, @PathVariable("id") int id) {
		gest.deleteProduit(id);
		return "redirect:/produits";

		
		
	}

}
