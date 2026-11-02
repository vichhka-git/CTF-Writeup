# Low Tide Ledger

OSINT, 69 points, 157 solves. A recovered two-speaker call is the entire prompt. Every line is a landmark clue that narrows one reclaimed waterfront district, and the final room comes from matching a single interior photograph against a property agency's public listing photos.

## What you are given

`low-tide-ledger.zip` contains one photograph, `room.jpg` (1246x832). There is no live service. The description supplies the format, which is the best guide to how many components the answer needs:

```
hiCTF{Development_City_Country_Agency_Room}
use hyphens for spaces, case-insensitive
example shape: hiCTF{Some-Project_Some-City_Some-Country_Some-Agency_1A}
```

So the answer is five parts: the reclaimed project, the metropolis, the country, the agency, and a room code built from a floor digit and a door letter.

## Reproduction

1. Date the land. "The summer Athens lit its flame" is the 2004 Athens Olympics, August 2004, and the speaker says the ground under the building was still open sea then. "Dredgers showed up half a year before Beijing's cauldron" puts the start of reclamation in early 2008, and "The planners promised seven years of dredging" is the announced reclamation schedule. The claim that it was still sea in 2004 and being dredged from 2008 fits one project.

2. Place the coast. "Dubai wouldn't let me face the Atlantic" removes the Gulf. "My clock matches Paris in winter and ignores the summer" is a UTC+1 zone with no daylight saving, which is West Africa Time.

3. Confirm the district. "The wall guarding me is stacked from five-ton concrete blocks, cast beside the water" is the sea wall built from huge cast concrete units, and "the old public beach is somewhere under my feet" is the beach that the reclamation buried. Together with Lagos as the obvious WAT metropolis: Eko Atlantic City, Lagos, Nigeria.

4. Resolve the tower cluster. "A cluster of towers named for five gems that never touched an oyster" is the five-pearl tower group at the district edge, with Black, Champagne, White, Indigo and Aqua Pearl towers. That gives the apartment complex, not the agency.

5. Find the agency. The speaker says it is "not a hotel, a small office that sells homes" inside those towers. The agency trading there is Platinum Eko Homes. Its public portfolio page embeds a property feed from its booking platform, and enumerating that feed returns seven listings, all of the form `<unit> Tower B - Eko Pearl Towers`, each with a numbered photo set.

6. Match the photograph by furniture, which is what the transcript tells you to do. `room.jpg` shows a dark walnut dining table with a black cross-trestle base, cognac leather bucket chairs with visible outer stitching and tapered dark legs, a blue-grey distressed rug, a tan leather sofa with an azure and magenta cushion group, full-height shears and a high ceiling vent. Listing `3C` matches all of it, including the vegetable print placemat and the chair seams. Its hallway photo also carries an Eiffel Tower triptych, which rhymes with the Paris clock line in the call. The other listings do not match the chairs or the table.

7. Take the room from the honest part of the listing. The matching listing is labelled `3C Tower B`, so floor 3 and door C. The transcript's remark that "the plate by the door is the only honest thing about it" is the hint that the unit label, not the marketing copy, is the reliable element. The local notes record the label; they do not preserve a separate close-up of the door plate itself.

8. Resolve "the original business name". The flag asks for the original business, and the trading brand is not it. A map search for real-estate offices at the towers returns Nairahomes Realty at Eko Pearl Towers, Victoria Island. Its place record predates the current brand: reviews from 2021 are written under the Platinum Shoreline name that the agency still uses in its directory contact details, while the present brand and its site are newer. That makes Nairahomes Realty the original business and Platinum Eko Homes the later trading identity. The unit record itself lists `Africa/Lagos`, which independently confirms the time zone clue.

9. Assemble and submit:

```
hiCTF{Eko-Atlantic-City_Lagos_Nigeria_Nairahomes-Realty_3C}
```

Three earlier attempts failed, and the failures are the two format traps. The first used the trading brand (`Platinum-Eko-Homes`). The second and third dropped the hyphen inside the project name and used the brand, then an acronym for the district. The accepted string keeps `Eko-Atlantic-City` intact and uses the registered agency name, with hyphens where the names have spaces and underscores only between the five components.

## Why it works

Each clue is public and independently checkable, and the sequence narrows a large search without guessing. The date bounds, the ocean side, the time zone, the concrete sea wall and the buried public beach all point at one project; the five-gem clue points at one tower group; and the agency's own portfolio supplies interior photographs that can be compared room by room. No reverse image search is required, and none of the local notes rely on one.

The part that needs a second source is the agency name. The visible brand is a marketing identity, and the answer wants the business that was there first. That only shows up in the older map listing and its review history, which is why the trading brand is the wrong answer even though every other component lines up.

## Flag

```
hiCTF{Eko-Atlantic-City_Lagos_Nigeria_Nairahomes-Realty_3C}
```
