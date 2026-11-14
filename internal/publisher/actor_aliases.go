package publisher

import (
	"strings"
	"sync"
)

// actorAliasGroups lists known threat-actor naming equivalences. Each
// inner slice is a single real-world group with every name a vendor or
// community uses for it. When cleanActors sees one of these names, it
// emits the entire group as actor entries on the brief — so a search
// for "Cozy Bear" finds the same briefs as "APT29".
//
// Sourced from MITRE ATT&CK's Groups page (attack.mitre.org/groups)
// and vendor codename pages. Hand-curated, not exhaustive — append a
// new group whenever a brief surfaces a name with multiple vendor
// codenames.
//
// Keep in sync with threat-feed/site/data/actor_aliases.yaml.
var actorAliasGroups = [][]string{
	{"APT29", "Cozy Bear", "NOBELIUM", "UNC2452", "Midnight Blizzard", "The Dukes"},
	{"APT28", "Fancy Bear", "Sofacy", "STRONTIUM", "Forest Blizzard", "Sednit", "Pawn Storm"},
	{"Lazarus Group", "HIDDEN COBRA", "LABYRINTH CHOLLIMA", "Diamond Sleet", "Zinc"},
	{"BlueNoroff", "STARDUST CHOLLIMA", "Sapphire Sleet", "TA444"},
	{"Andariel", "STONEFLY", "Onyx Sleet", "Plutonium"},
	{"Kimsuky", "Black Banshee", "Velvet Chollima", "Emerald Sleet", "Thallium"},
	{"APT41", "Wicked Panda", "BARIUM", "Brass Typhoon", "Winnti", "Double Dragon"},
	{"APT40", "Leviathan", "BRONZE MOHAWK", "Mulberry Typhoon", "Gingham Typhoon"},
	{"APT35", "Charming Kitten", "TA453", "Mint Sandstorm", "Phosphorus"},
	{"APT34", "OilRig", "Hazel Sandstorm", "Helix Kitten"},
	{"APT33", "Refined Kitten", "Peach Sandstorm", "Elfin"},
	{"Turla", "Snake", "Venomous Bear", "Secret Blizzard", "Iron Hunter"},
	{"Sandworm", "BlackEnergy", "Voodoo Bear", "Seashell Blizzard", "IRIDIUM"},
	{"FIN7", "Carbon Spider", "Sangria Tempest"},
	{"FIN8", "Syssphinx"},
	{"Scattered Spider", "UNC3944", "Octo Tempest", "Roasted 0ktapus", "Muddled Libra", "Star Fraud"},
	{"Volt Typhoon", "Vanguard Panda", "Bronze Silhouette", "Insidious Taurus"},
	{"Salt Typhoon", "GhostEmperor", "FamousSparrow", "UNC5807"},
	{"Flax Typhoon", "Ethereal Panda"},
	{"BlackCat", "ALPHV", "Noberus"},
	{"Conti", "Wizard Spider"},
	{"Cl0p", "TA505", "FIN11", "GRACEFUL SPIDER"},
	{"Black Basta", "BlackBasta", "UNC4393"},
	{"Akira"},
	{"Qilin", "Agenda"},
	{"LockBit", "BITWISE SPIDER"},
	{"Play", "PlayCrypt"},
	{"BianLian"},
	{"RansomHub"},
	{"Royal", "DEV-0569"},
	{"Medusa"},
	{"Hive"},
	{"REvil", "Sodinokibi", "GOLD SOUTHFIELD"},
	{"DarkSide", "CARBON SPIDER"},
	{"TA577", "Mustard Tempest"},
	{"TA571"},
	{"Storm-0501"},
	{"Storm-0978", "RomCom", "Tropical Scorpius"},
	{"TrueChaos"},
}

var (
	actorAliasIndex     map[string][]string
	actorAliasIndexOnce sync.Once
)

func buildActorAliasIndex() {
	actorAliasIndex = make(map[string][]string, len(actorAliasGroups)*4)
	for _, g := range actorAliasGroups {
		for _, name := range g {
			actorAliasIndex[strings.ToLower(name)] = g
		}
	}
}

// expandAliases returns the full alias group containing name (case-
// insensitive), or nil if name is not in any group. The returned slice
// preserves the canonical casing from actorAliasGroups, so callers can
// substitute it for the original input without losing form.
func expandAliases(name string) []string {
	actorAliasIndexOnce.Do(buildActorAliasIndex)
	return actorAliasIndex[strings.ToLower(strings.TrimSpace(name))]
}
